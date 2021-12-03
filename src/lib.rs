mod crc;
mod error;

use crate::error::Result;

use modular_bitfield::error::InvalidBitPattern;
use modular_bitfield::error::OutOfBounds;
use modular_bitfield::prelude::*;

use std::fmt::Debug;
use std::fs::File;
use std::io;
use std::io::prelude::*;

use error::*;

const BCACHE_SB_VERSION_BDEV: u64 = 1;
const BCACHE_SB_VERSION_CDEV_WITH_UUID: u64 = 3;
const _BCACHE_SB_VERSION_CDEV_WITH_FEATURES: u64 = 5;
const _BCACHE_SB_VERSION_BDEV_WITH_FEATURES: u64 = 6;

const MAX_CACHES_PER_SET: u16 = 8;

const BCACHE_MAGIC: [u8; 16] = [
    0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca, 0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81,
];

fn bcache_crc64(input: &[u8]) -> u64 {
    crc::crc64_be(u64::MAX, input) ^ u64::MAX
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
#[derive(Debug)]
pub struct CacheFlags {
    pub sync: bool,
    pub discard: bool,
    pub replacement: CacheReplacement,
    #[skip]
    __: B60,
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
#[derive(Debug)]
pub struct BackingFlags {
    pub mode: CacheMode,
    #[skip]
    __: B57,
    pub state: BackingState,
    #[skip]
    ___: B1,
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

fn get_d_8(input: &[u8]) -> nom::IResult<&[u8], [u64; 8]> {
    let mut buf = [0; 8];
    let (rest, _) = nom::multi::fill(nom::number::complete::le_u64, &mut buf)(input)?;
    Ok((rest, buf))
}

fn get_bkey(ptrs: usize) -> impl Fn(&[u8]) -> nom::IResult<&[u8], BKey> {
    move |input| {
        let (rest, key) = nom::number::complete::le_u128(input)?;

        let mut raw_ptrs = vec![0; ptrs];

        let (rest, _) = nom::multi::fill(nom::number::complete::le_u64, &mut raw_ptrs)(rest)?;

        let ret = BKey {
            key: key.into(),
            ptrs: raw_ptrs.into_iter().map(|rp| rp.into()).collect(),
        };
        Ok((rest, ret))
    }
}

impl BCacheSB {
    fn read(mut dev: impl Read) -> Result<(BCacheSB, [u8; 16])> {
        let mut page = [0u8; 4096];

        dev.read_exact(&mut page)?;
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
            return Err(BCacheRecoveryError::BCacheError(
                BCacheErrorKind::UnsupportedVersion(sb.version),
            ));
        }

        if sb.offset != 8 {
            return Err(BCacheRecoveryError::BCacheError(
                BCacheErrorKind::BadOffset(sb.offset),
            ));
        }

        sb.magic.copy_from_slice(parts.2);
        if sb.magic != BCACHE_MAGIC {
            return Err(BCacheRecoveryError::BCacheError(BCacheErrorKind::BadMagic(
                sb.magic,
            )));
        }

        let header_size = after_header.as_ptr() as usize - header.as_ptr() as usize;
        let crc =
            bcache_crc64(&header[0..(header_size + 8 * sb.njournal_buckets_or_keys as usize)]);
        if crc != csum {
            return Err(BCacheRecoveryError::BCacheError(
                BCacheErrorKind::BadChecksum(csum, crc),
            ));
        }

        sb.uuid.copy_from_slice(parts.3);
        if sb.uuid.iter().all(|&x| x == 0) {
            return Err(BCacheRecoveryError::BCacheError(BCacheErrorKind::BadUuid(
                sb.uuid,
            )));
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

    fn jset_magic(&self) -> u64 {
        u64::from_ne_bytes(self.set_uuid[..8].try_into().unwrap()) ^ 0x245235c1a3625032
    }

    fn pset_magic(&self) -> u64 {
        u64::from_ne_bytes(self.set_uuid[..8].try_into().unwrap()) ^ 0x6750e15f87337f91
    }
}

#[derive(Debug)]
pub struct BCacheCache {
    backing_file: File,
    pub sb: BCacheSB,
    pub nbuckets: u64,
    pub block_size: u16,
    pub bucket_size: u64,
    pub nr_in_set: u16,
    pub nr_this_dev: u16,
    pub flags: CacheFlags,
    pub prio_entries: Vec<BucketPrios>,
}

#[derive(Debug)]
pub struct BucketPrios {
    pub prio: u16,
    pub gen: u8,
}

#[derive(Debug)]
pub struct JournalBlock {
    pub entries: Vec<JournalSet>,
}

#[derive(Debug)]
pub struct JournalSet {
    pub seq: u64,
    pub version: u32,
    pub keys: u32,
    pub last_seq: u64,
    pub uuid_bucket: BKey,
    pub btree_root: BKey,
    pub btree_level: u16,
    pub prio_bucket: [u64; 8],
}

#[bitfield(bits = 128)]
#[repr(u128)]
#[derive(Clone, Copy, Debug)]
pub struct BKeyKey {
    pub inode: B20,
    pub size: B16,
    pub dirty: bool,
    #[skip]
    __: B18,
    #[skip]
    pad1: B1,
    pub csum: B2,
    #[skip]
    pad0: B2,
    pub ptrs: B3,
    #[skip]
    __: B1,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct BKey {
    pub key: BKeyKey,
    pub ptrs: Vec<BPtr>,
}

#[bitfield(bits = 64)]
#[repr(u64)]
#[derive(Clone, Copy, Debug)]
pub struct BPtr {
    pub gen: u8,
    pub offset: Sector43,
    pub dev: B12,
    #[skip]
    __: B1,
}

impl BPtr {
    pub fn is_available(&self, _ca: &BCacheCache) -> bool {
        self.dev() < MAX_CACHES_PER_SET
    }

    pub fn bucket_remainder(&self, ca: &BCacheCache) -> u64 {
        self.offset().as_bytes() & (ca.bucket_size - 1)
    }

    pub fn bucket_number(&self, ca: &BCacheCache) -> u64 {
        self.offset().as_bytes() / ca.bucket_size
    }
}

#[derive(Debug)]
pub struct Sector(u64);

pub enum Sector43 {}

impl Sector {
    pub fn as_bytes(&self) -> u64 {
        self.0 * 512
    }
}

impl modular_bitfield::Specifier for Sector43 {
    const BITS: usize = 43;

    type Bytes = u64;
    type InOut = Sector;

    #[inline]
    fn into_bytes(input: Self::InOut) -> std::result::Result<Self::Bytes, OutOfBounds> {
        if input.0 > 1 << Self::BITS {
            return Err(OutOfBounds);
        }
        Ok(input.0)
    }

    #[inline]
    fn from_bytes(
        bytes: Self::Bytes,
    ) -> std::result::Result<Self::InOut, InvalidBitPattern<Self::Bytes>> {
        if bytes > 1 << Self::BITS {
            return Err(InvalidBitPattern {
                invalid_bytes: bytes,
            });
        }
        Ok(Sector(bytes))
    }
}

impl BKey {
    fn btree_ptr_invalid(&self, ca: &BCacheCache) -> bool {
        if self.key.ptrs() == 0 || self.key.size() == 0 || self.key.dirty() {
            return false;
        }

        self.ptr_invalid(ca)
    }

    fn ptr_invalid(&self, ca: &BCacheCache) -> bool {
        for p in self.ptrs.iter() {
            if p.is_available(ca) {
                let other = p.bucket_remainder(ca);
                let bucket_number = p.bucket_number(ca);

                if u64::from(self.key.size()) + other > ca.bucket_size
                    || bucket_number < ca.sb.first_bucket.into()
                    || bucket_number >= ca.nbuckets
                {
                    return true;
                }
            }
        }
        false
    }
}

impl JournalSet {
    fn read<'a>(cache: &BCacheCache, buf: &'a [u8]) -> Result<(&'a [u8], Option<Self>)> {
        let (header, csum) = nom::number::complete::le_u64(buf)?;

        let (left, parts) = nom::sequence::tuple((
            nom::number::complete::le_u64,          // magic
            nom::number::complete::le_u64,          // seq
            nom::number::complete::le_u32,          // version
            nom::number::complete::le_u32,          // keys
            nom::number::complete::le_u64,          // last_seq
            get_bkey(6),                            // uuid_bucket
            get_bkey(6),                            // btree_root
            nom::number::complete::le_u16,          // btree_level
            nom::bytes::complete::take(3 * 2usize), // pad
            get_d_8,                                // prio_bucket
        ))(header)?;

        if parts.0 != cache.sb.jset_magic() {
            return Ok((&buf[0..0], None));
        }

        let header_size = left.as_ptr() as usize - header.as_ptr() as usize;
        let jset_size = header_size + 8 * parts.3 as usize;
        let crc = bcache_crc64(&header[0..jset_size]);
        if crc != csum {
            return Err(BCacheRecoveryError::BCacheError(
                BCacheErrorKind::BadChecksum(csum, crc),
            ));
        }

        let block_size_usize = usize::from(cache.block_size);
        let size_with_pad: usize = (jset_size + block_size_usize - 1) & !(block_size_usize - 1);
        let buf = &buf[size_with_pad..];

        Ok((
            buf,
            Some(JournalSet {
                seq: parts.1,
                version: parts.2,
                keys: parts.3,
                last_seq: parts.4,
                uuid_bucket: parts.5,
                btree_root: parts.6,
                btree_level: parts.7,
                prio_bucket: parts.9,
            }),
        ))
    }
}

impl BCacheCache {
    fn new(sb: BCacheSB, sb_data: [u8; 16], f: File) -> Result<BCacheCache> {
        let (_, parts) = nom::sequence::tuple((
            nom::number::complete::le_u64, // nbuckets
            nom::number::complete::le_u16, // block_size
            nom::number::complete::le_u16, // bucket_size
            nom::number::complete::le_u16, // nr_in_set
            nom::number::complete::le_u16, // nr_this_dev
        ))(&sb_data[..])?;

        let mut ret = BCacheCache {
            backing_file: f,
            nbuckets: parts.0,
            block_size: parts.1 * 512,
            bucket_size: u64::from(parts.2) * 512,
            nr_in_set: parts.3,
            nr_this_dev: parts.4,
            flags: sb.flags.into(),
            prio_entries: vec![],
            sb,
        };
        if !ret.flags.sync() {
            Err(BCacheRecoveryError::UnsupportedFeature(
                UnsupportedFeatureKind::NonSynchronousCache,
            ))
        } else {
            let journal_entries = ret.read_journal()?;
            let journal_entry = journal_entries.last().unwrap();

            ret.read_prios(journal_entry.prio_bucket[ret.nr_this_dev as usize])?;

            if journal_entry.btree_root.btree_ptr_invalid(&ret) {
                return Err(BCacheRecoveryError::BCacheError(
                    BCacheErrorKind::BadBtreeKey(journal_entry.btree_root.clone()),
                ));
            }

            Ok(ret)
        }
    }

    fn read_journal(&mut self) -> Result<Vec<JournalSet>> {
        let journal_buckets = (0..self.sb.njournal_buckets_or_keys.into())
            .map(|i| self.read_journal_bucket(i))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let max_last_seq = journal_buckets
            .iter()
            .flat_map(|j| j.entries.iter().map(|e| e.last_seq))
            .max()
            .unwrap();
        let mut real_entries: Vec<_> = journal_buckets
            .into_iter()
            .flat_map(|j| j.entries)
            .filter(|e| e.seq >= max_last_seq)
            .collect();
        real_entries.sort_by_key(|e| e.seq);
        Ok(real_entries)
    }

    fn read_journal_bucket(&mut self, index: usize) -> Result<JournalBlock> {
        let bucket_start = self.bucket_to_byte_offset(self.sb.data[index]);

        let mut buf = vec![0; self.bucket_size.try_into()?];
        self.backing_file.seek(io::SeekFrom::Start(bucket_start))?;
        self.backing_file.read_exact(&mut buf)?;

        let mut entries = vec![];

        let mut to_parse = &buf[..];
        while !to_parse.is_empty() {
            let (left, jseto) = JournalSet::read(self, to_parse)?;
            to_parse = left;
            if let Some(jset) = jseto {
                entries.push(jset);
            }
        }

        Ok(JournalBlock { entries })
    }

    fn read_prios(&mut self, bucket: u64) -> Result<()> {
        let mut buf = vec![0; self.bucket_size.try_into()?];
        self.backing_file
            .seek(io::SeekFrom::Start(self.bucket_to_byte_offset(bucket)))?;
        self.backing_file.read_exact(&mut buf)?;

        let (header, csum) = nom::number::complete::le_u64(&buf[..])?;
        let calc_csum = bcache_crc64(header);
        if calc_csum != csum {
            return Err(BCacheRecoveryError::BCacheError(
                BCacheErrorKind::BadChecksum(csum, calc_csum),
            ));
        }

        let (mut rest, parts) = nom::sequence::tuple((
            nom::number::complete::le_u64, // magic
            nom::number::complete::le_u64, // seq
            nom::number::complete::le_u32, // version
            nom::number::complete::le_u32, // pad
            nom::number::complete::le_u64, // next_bucket
        ))(header)?;

        if parts.0 != self.sb.pset_magic() {
            return Err(BCacheRecoveryError::BCacheError(
                BCacheErrorKind::BadSetMagic(parts.0),
            ));
        }

        while rest.len() >= 3 && u64::try_from(self.prio_entries.len())? < self.nbuckets {
            let (newrest, parts) = nom::sequence::tuple((
                nom::number::complete::le_u16, // prio
                nom::number::complete::le_u8,  // gen
            ))(rest)?;
            rest = newrest;

            self.prio_entries.push(BucketPrios {
                prio: parts.0,
                gen: parts.1,
            })
        }

        if u64::try_from(self.prio_entries.len())? < self.nbuckets {
            self.read_prios(parts.4)
        } else {
            Ok(())
        }
    }

    fn bucket_to_byte_offset(&self, bucket_number: u64) -> u64 {
        bucket_number * self.bucket_size
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
            sb,
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
        BCacheDev::Cache(BCacheCache::new(sb, data, f)?)
    } else {
        BCacheDev::Backing(BCacheBacking::new(sb)?)
    })
}
