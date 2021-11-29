mod crc;
mod error;

use crate::error::Result;

use modular_bitfield::prelude::*;
use nom;

use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io;
use std::io::prelude::*;

use error::*;

const BCACHE_SB_VERSION_BDEV: u64 = 1;
const BCACHE_SB_VERSION_CDEV_WITH_UUID: u64 = 3;
const _BCACHE_SB_VERSION_CDEV_WITH_FEATURES: u64 = 5;
const _BCACHE_SB_VERSION_BDEV_WITH_FEATURES: u64 = 6;

const BCACHE_MAGIC: [u8; 16] = [
    0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca, 0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81,
];

fn bcache_crc64(input: &[u8]) -> u64 {
    return crc::crc64_be(u64::MAX, input) ^ u64::MAX;
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 2]
pub enum CacheReplacement {
    Lru,
    Fifo,
    Random,
}

#[bitfield(bits = 64)]
#[repr(u64)]
pub struct CacheFlags {
    pub sync: bool,
    pub discard: bool,
    pub replacement: CacheReplacement,
    #[skip]
    __: B60,
}

impl Debug for CacheFlags {
    fn fmt(&self, f: &mut Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(
            f,
            "CacheFlags {{ sync: {:?}, discard: {:?}, replacement: {:?} }}",
            self.sync(),
            self.discard(),
            self.replacement()
        )
    }
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 4]
pub enum CacheMode {
    WriteThough,
    WriteBack,
    WriteAround,
    None,
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 2]
pub enum BackingState {
    None,
    Clean,
    Dirty,
    Stale,
}

#[bitfield(bits = 64)]
#[repr(u64)]
pub struct BackingFlags {
    pub mode: CacheMode,
    #[skip]
    __: B57,
    state: BackingState,
    #[skip]
    ___: B1,
}

impl Debug for BackingFlags {
    fn fmt(&self, f: &mut Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(
            f,
            "BackingFlags {{ mode: {:?}, state: {:?} }}",
            self.mode(),
            self.state()
        )
    }
}

#[derive(Debug)]
pub struct BCacheSB {
    pub offset: u64,
    pub version: u64,
    pub magic: [u8; 16],
    pub uuid: [u8; 16],
    pub set_uuid: [u8; 16],
    pub label: [u8; 32],
    pub flags: u64,
    pub seq: u64,
    pub feature_compat: u64,
    pub feature_incompat: u64,
    pub feature_ro_compat: u64,
    pub last_mount: u32,
    pub first_bucket: u16,
    pub njournal_buckets_or_keys: u16,
    pub data: [u64; 256],
}

fn get_d(input: &[u8]) -> nom::IResult<&[u8], [u64; 256]> {
    let mut buf = [0; 256];
    let (rest, _) = nom::multi::fill(nom::number::complete::le_u64, &mut buf)(input)?;
    Ok((rest, buf))
}

impl BCacheSB {
    fn read(mut dev: impl Read) -> Result<(BCacheSB, [u8; 16])> {
        let mut page = [0u8; 4096];

        dev.read(&mut page)?;
        let page = page;

        let (header, csum) = nom::number::complete::le_u64(&page[..])?;

        let (after_header, parts) = nom::sequence::tuple((
            nom::number::complete::le_u64,          //offset
            nom::number::complete::le_u64,          //version
            nom::bytes::complete::take(16usize),    //magic
            nom::bytes::complete::take(16usize),    //uuid
            nom::bytes::complete::take(16usize),    //set_uuid/set_magic
            nom::bytes::complete::take(32usize),    //label (SB_LABEL_SIZE == 32)
            nom::number::complete::le_u64,          // flags
            nom::number::complete::le_u64,          // seq
            nom::number::complete::le_u64,          // feature_compat
            nom::number::complete::le_u64,          // feature_incompat
            nom::number::complete::le_u64,          // feature_ro_compat
            nom::bytes::complete::take(5usize * 8), //pad
            nom::bytes::complete::take(16usize),    //device_data (cache/backing union)
            nom::number::complete::le_u32,          // last_mount
            nom::number::complete::le_u16,          // first_bucket
            nom::number::complete::le_u16,          // njournal_buckets/keys
        ))(header)?;

        let mut sb = BCacheSB {
            offset: parts.0,
            version: parts.1,
            magic: [0; 16],
            uuid: [0; 16],
            set_uuid: [0; 16],
            label: [0; 32],
            flags: parts.6,
            seq: parts.7,
            feature_compat: parts.8,
            feature_incompat: parts.9,
            feature_ro_compat: parts.10,
            last_mount: parts.13,
            first_bucket: parts.14,
            njournal_buckets_or_keys: parts.15,
            data: get_d(after_header)?.1,
        };

        if sb.version != BCACHE_SB_VERSION_CDEV_WITH_UUID && sb.version != BCACHE_SB_VERSION_BDEV {
            return Err(BCacheError::BCacheError(
                BCacheErrorKind::UnsupportedVersion(sb.version),
            ));
        }

        if sb.offset != 8 {
            return Err(BCacheError::BCacheError(BCacheErrorKind::BadOffset(
                sb.offset,
            )));
        }

        sb.magic.copy_from_slice(parts.2);
        if sb.magic != BCACHE_MAGIC {
            return Err(BCacheError::BCacheError(BCacheErrorKind::BadMagic(
                sb.magic,
            )));
        }

        let header_size = after_header.as_ptr() as usize - header.as_ptr() as usize;
        let crc =
            bcache_crc64(&header[0..(header_size + 8 * sb.njournal_buckets_or_keys as usize)]);
        if crc != csum {
            return Err(BCacheError::BCacheError(BCacheErrorKind::BadChecksum(
                csum, crc,
            )));
        }

        sb.uuid.copy_from_slice(parts.3);
        if sb.uuid.iter().all(|&x| x == 0) {
            return Err(BCacheError::BCacheError(BCacheErrorKind::BadUuid(sb.uuid)));
        }

        sb.set_uuid.copy_from_slice(parts.4);
        sb.label.copy_from_slice(parts.5);

        let mut device_data = [0; 16];
        device_data[..].copy_from_slice(parts.12);
        Ok((sb, device_data))
    }

    fn is_cache(&self) -> bool {
        self.version == BCACHE_SB_VERSION_CDEV_WITH_UUID
    }
}

#[derive(Debug)]
pub struct BCacheCache {
    pub sb: BCacheSB,
    pub nbuckets: u64,
    pub block_size: u16,
    pub bucket_size: u64,
    pub nr_in_set: u16,
    pub nr_this_dev: u16,
    pub flags: CacheFlags,
}

impl BCacheCache {
    fn new(sb: BCacheSB, sb_data: [u8; 16]) -> Result<BCacheCache> {
        let (_, parts) = nom::sequence::tuple((
            nom::number::complete::le_u64, // nbuckets
            nom::number::complete::le_u16, // block_size
            nom::number::complete::le_u16, // bucket_size
            nom::number::complete::le_u16, // nr_in_set
            nom::number::complete::le_u16, // nr_this_dev
        ))(&sb_data[..])?;

        Ok(BCacheCache {
            nbuckets: parts.0,
            block_size: parts.1,
            bucket_size: parts.2.into(),
            nr_in_set: parts.3,
            nr_this_dev: parts.4,
            flags: sb.flags.into(),
            sb: sb,
        })
    }
}

#[derive(Debug)]
pub struct BCacheBacking {
    pub sb: BCacheSB,
    pub data_offset: u64,
    pub flags: BackingFlags,
}

impl BCacheBacking {
    fn new(sb: BCacheSB) -> Result<BCacheBacking> {
        Ok(BCacheBacking {
            data_offset: 16,
            flags: sb.flags.into(),
            sb: sb,
        })
    }
}

pub enum BCacheDev {
    Backing(BCacheBacking),
    Cache(BCacheCache),
}

pub fn open_device(path: &str) -> Result<BCacheDev> {
    let mut f = File::open(path)?;

    f.seek(io::SeekFrom::Start(4096))?; // Superblock offset

    let (sb, data) = BCacheSB::read(&f)?;
    Ok(if sb.is_cache() {
        BCacheDev::Cache(BCacheCache::new(sb, data)?)
    } else {
        BCacheDev::Backing(BCacheBacking::new(sb)?)
    })
}
