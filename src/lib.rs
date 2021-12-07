mod crc;
pub mod error;

use serde::ser::*;
use serde::Serialize;
use serde::Serializer;

use crate::error::Result;

use modular_bitfield::error::InvalidBitPattern;
use modular_bitfield::error::OutOfBounds;
use modular_bitfield::prelude::*;
use nom::error::{ErrorKind, ParseError};
use nom::Err;

use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::rc::Rc;

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
    bcache_crc64_start(u64::MAX, input)
}

fn bcache_crc64_start(start: u64, input: &[u8]) -> u64 {
    crc::crc64_be(start, input) ^ u64::MAX
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
#[derive(Debug, Serialize)]
pub struct BackingFlags {
    pub mode: CacheMode,
    #[skip]
    __: B57,
    pub state: BackingState,
    #[skip]
    ___: B1,
}

#[derive(Debug)]
#[derive(Serialize)]
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
    #[serde(skip_serializing)]
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

fn get_d8_16(input: &[u8]) -> nom::IResult<&[u8], [u8; 16]> {
    let mut buf = [0; 16];
    let (rest, _) = nom::multi::fill(nom::number::complete::le_u8, &mut buf)(input)?;
    Ok((rest, buf))
}

fn get_d8_32(input: &[u8]) -> nom::IResult<&[u8], [u8; 32]> {
    let mut buf = [0; 32];
    let (rest, _) = nom::multi::fill(nom::number::complete::le_u8, &mut buf)(input)?;
    Ok((rest, buf))
}

fn get_bkey(ptrs: Option<usize>) -> impl Fn(&[u8]) -> nom::IResult<&[u8], BKey> {
    move |input| {
        let (rest, key) = nom::number::complete::u128(nom::number::Endianness::Native)(input)?;
        let key = BKeyKey::from(key);

        let mut raw_ptrs = vec![0; key.ptrs().into()];

        let (mut rest, _) = nom::multi::fill(nom::number::complete::le_u64, &mut raw_ptrs)(rest)?;
        if let Some(ptrs) = ptrs {
            rest = match ptrs.checked_sub(raw_ptrs.len()) {
                Some(x) => {
                    let (rest, _) = nom::bytes::complete::take(x * 8)(rest)?;
                    rest
                }
                None => {
                    return Err(Err::Failure(ParseError::from_error_kind(
                        rest,
                        ErrorKind::Count,
                    )))
                }
            }
        }

        let ret = BKey {
            key,
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

    fn bset_magic(&self) -> u64 {
        u64::from_ne_bytes(self.set_uuid[..8].try_into().unwrap()) ^ 0x90135c78b99e07f5
    }
}

#[derive(Debug)]
#[derive(Serialize)]
pub struct BCacheCache {
    #[serde(skip_serializing)]
    backing_file: File,
    pub sb: BCacheSB,
    pub nbuckets: u64,
    pub block_size: u16,
    pub bucket_size: u64,
    pub nr_in_set: u16,
    pub nr_this_dev: u16,
    #[serde(skip_serializing)]
    pub flags: CacheFlags,
    #[serde(skip_serializing)]
    pub prio_entries: Vec<BucketPrios>,
    pub root: Option<Rc<BTree>>,
    pub uuids: Option<Vec<Uuid>>,
    pub journal_log: Vec<BKey>,
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
    pub keys: Vec<BKey>,
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
    pub size: Sector16,
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
    pub offset: Sector,
}

#[derive(Debug, Clone, Serialize)]
pub struct BKey {
    pub key: BKeyKey,
    pub ptrs: Vec<BPtr>,
}

impl Serialize for BKeyKey {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
        where S: Serializer { 
        let mut k = s.serialize_struct("BkeyKey", 6)?;
        k.serialize_field("inode", &self.inode())?;
        k.serialize_field("size", &self.size().0)?;
        k.serialize_field("dirty", &self.dirty())?;
        k.serialize_field("csum", &self.csum())?;
        k.serialize_field("ptrs", &self.ptrs())?;
        k.serialize_field("offset", &self.offset().0)?;
        k.end()
    }
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

impl Serialize for BPtr {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
        where S: Serializer { 
        let mut k = s.serialize_struct("BkeyKey", 3)?;
        k.serialize_field("gen", &self.gen())?;
        k.serialize_field("offset", &self.offset().0)?;
        k.serialize_field("dev", &self.dev())?;
        k.end()
    }
}

#[derive(Debug, Serialize)]
pub struct BTree {
    pub seq: u64,
    pub flags: u32,
    pub level: u8,
    pub key: BKey,
    pub pointers: BTreeChild,
}

#[derive(Debug)]
pub enum BTreeChild {
    Data(Vec<BKey>),
    Children(Vec<Rc<BTree>>),
}

impl BTree {
    pub fn new(bkey: &BKey, seq: u64, level: u8, pointers: BTreeChild) -> Rc<Self> {
        Rc::new(Self {
            seq,
            flags: 0,
            level,
            pointers,
            key: bkey.clone(),
        })
    }

    pub fn read(ca: &mut BCacheCache, bkey: &BKey, level: u8) -> Result<Rc<Self>> {
        let block_size = usize::from(ca.block_size);
        let mut buf = vec![0u8; bkey.key.size().as_bytes().try_into()?];
        ca.backing_file
            .seek(io::SeekFrom::Start(bkey.ptrs[0].offset().as_bytes()))?;
        ca.backing_file.read_exact(&mut buf)?;
        let mut buf = &buf[..];
        let mut seq = None;
        let mut keys = vec![];

        while !buf.is_empty() {
            let (header, csum) = nom::number::complete::le_u64(buf)?;
            let (rest, parts) = nom::sequence::tuple((
                nom::number::complete::le_u64, // magic
                nom::number::complete::le_u64, // seq
                nom::number::complete::le_u32, // version
                nom::number::complete::le_u32, // keys
            ))(header)?;

            if let Some(x) = seq {
                if x != parts.1 {
                    break;
                }
            } else {
                seq = Some(parts.1)
            }

            if parts.2 != 1 {
                return Err(BCacheRecoveryError::BCacheError(
                    BCacheErrorKind::UnsupportedVersion(parts.2.into()),
                ));
            }

            if parts.0 != ca.sb.bset_magic() {
                return Err(BCacheRecoveryError::BCacheError(
                    BCacheErrorKind::BadSetMagic(parts.0),
                ));
            }

            let crc = bcache_crc64_start(
                (bkey.ptrs[0]).try_into().unwrap(),
                &header[0..(24 + parts.3 * 8).try_into()?],
            );
            if crc != csum {
                return Err(BCacheRecoveryError::BCacheError(
                    BCacheErrorKind::BadChecksum(csum, crc),
                ));
            }

            let mut rest = &rest[..(parts.3 * 8).try_into()?];
            while !rest.is_empty() {
                let (resta, key) = get_bkey(None)(rest)?;
                keys.push(key);

                rest = resta;
            }

            let offset = rest.as_ptr() as usize - buf.as_ptr() as usize;
            let offset = (offset + block_size - 1) & !(block_size - 1);
            buf = &buf[offset..];
        }

        while !buf.is_empty() {
            let (_, tseq) = nom::number::complete::le_u64(&buf[16..])?;
            if let Some(seq) = seq {
                if seq == tseq {
                    return Err(BCacheRecoveryError::BCacheError(BCacheErrorKind::BadBtree(
                        bkey.clone(),
                    )));
                }
            }
            buf = &buf[block_size..];
        }

        let children = if level == 0 {
            BTreeChild::Data(keys)
        } else {
            let mut children_vec = vec![];
            for child_key in keys {
                let bucket = ca.offset_to_bucket(child_key.ptrs[0].offset().as_bytes());
                if bkey.ptrs[0].gen() == ca.prio_entries[usize::try_from(bucket)?].gen {
                    children_vec.push(BTree::read(ca, &child_key, level - 1)?);
                }
            }
            BTreeChild::Children(children_vec)
        };
        Ok(Self::new(bkey, seq.unwrap(), level, children))
    }
}

#[derive(Debug, Serialize)]
pub struct Uuid {
    pub uuid: [u8; 16],
    pub label: [u8; 32],
    pub first_reg: u32,
    pub last_reg: u32,
    pub invalidated: u32,
    pub flags: UuidFlags,
    pub sectors: u64,
}

#[bitfield(bits = 32)]
#[repr(u32)]
#[derive(Debug, Serialize)]
pub struct UuidFlags {
    pub flash_only: bool,
    #[skip]
    __: B31,
}

impl Uuid {
    pub fn read(ca: &mut BCacheCache, journal_entry: &JournalSet) -> Result<Vec<Uuid>> {
        let bkey = &journal_entry.uuid_bucket;
        if journal_entry.version != 1 {
            return Err(BCacheRecoveryError::BCacheError(
                BCacheErrorKind::UnsupportedVersion(journal_entry.version.into()),
            ));
        }

        let mut ret = vec![];

        let mut buf = vec![0; ca.bucket_size.try_into()?];
        ca.backing_file
            .seek(io::SeekFrom::Start(bkey.ptrs[0].offset().as_bytes()))?;
        ca.backing_file.read_exact(&mut buf)?;
        let mut buf = &buf[..];

        while buf.len() >= 128 {
            let (_, parts) = nom::sequence::tuple((
                get_d8_16,                     // uuid
                get_d8_32,                     // label
                nom::number::complete::le_u32, // first_reg
                nom::number::complete::le_u32, // last_reg
                nom::number::complete::le_u32, // invalidated
                nom::number::complete::le_u32, // flags
                nom::number::complete::le_u64, // sectors
            ))(buf)?;

            if parts.0 != [0; 16] {
                ret.push(Uuid {
                    uuid: parts.0,
                    label: parts.1,
                    first_reg: parts.2,
                    last_reg: parts.3,
                    invalidated: parts.4,
                    flags: parts.5.into(),
                    sectors: parts.6,
                });
            }

            buf = &buf[128..];
        }

        Ok(ret)
    }
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
pub enum Sector16 {}

impl Sector {
    pub fn as_bytes(&self) -> u64 {
        self.0 * 512
    }

    pub fn from_byte_offset(offset: u64) -> Self {
        Self(offset / 512)
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

impl modular_bitfield::Specifier for Sector16 {
    const BITS: usize = 16;

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

impl modular_bitfield::Specifier for Sector {
    const BITS: usize = 64;

    type Bytes = u64;
    type InOut = Sector;

    #[inline]
    fn into_bytes(input: Self::InOut) -> std::result::Result<Self::Bytes, OutOfBounds> {
        Ok(input.0)
    }

    #[inline]
    fn from_bytes(
        bytes: Self::Bytes,
    ) -> std::result::Result<Self::InOut, InvalidBitPattern<Self::Bytes>> {
        Ok(Sector(bytes))
    }
}

impl BKey {
    fn btree_ptr_invalid(&self, ca: &BCacheCache) -> bool {
        if self.key.ptrs() == 0 || self.key.size().0 == 0 || self.key.dirty() {
            return false;
        }

        self.ptr_invalid(ca)
    }

    fn ptr_invalid(&self, ca: &BCacheCache) -> bool {
        for p in self.ptrs.iter() {
            if p.is_available(ca) {
                let other = p.bucket_remainder(ca);
                let bucket_number = p.bucket_number(ca);

                if self.key.size().as_bytes() + other > ca.bucket_size
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
            get_bkey(Some(6)),                      // uuid_bucket
            get_bkey(Some(6)),                      // btree_root
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

        let mut keys = vec![];
        let mut left = &left[..8usize * usize::try_from(parts.3)?];
        while !left.is_empty() {
            let (lefta, bkey) = get_bkey(None)(left)?;
            keys.push(bkey);
            left = lefta;
        }

        let block_size_usize = usize::from(cache.block_size);
        let size_with_pad: usize = (jset_size + block_size_usize - 1) & !(block_size_usize - 1);
        let buf = &buf[size_with_pad..];

        Ok((
            buf,
            Some(JournalSet {
                seq: parts.1,
                version: parts.2,
                last_seq: parts.4,
                uuid_bucket: parts.5,
                btree_root: parts.6,
                btree_level: parts.7,
                prio_bucket: parts.9,
                keys,
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
            root: None,
            uuids: None,
            journal_log: vec![],
            sb,
        };
        if !ret.flags.sync() {
            Err(BCacheRecoveryError::UnsupportedFeature(
                UnsupportedFeatureKind::NonSynchronousCache,
            ))
        } else {
            let journal_entries = ret.read_journal()?;
            let journal_entry = journal_entries.into_iter().last().unwrap();

            ret.read_prios(journal_entry.prio_bucket[ret.nr_this_dev as usize])?;

            if journal_entry.btree_root.btree_ptr_invalid(&ret) {
                return Err(BCacheRecoveryError::BCacheError(
                    BCacheErrorKind::BadBtreeKey(journal_entry.btree_root.clone()),
                ));
            }

            ret.root = Some(BTree::read(
                &mut ret,
                &journal_entry.btree_root,
                journal_entry.btree_level.try_into()?,
            )?);

            ret.uuids = Some(Uuid::read(&mut ret, &journal_entry)?);

            ret.journal_log = journal_entry.keys;

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

    fn offset_to_bucket(&self, offset: u64) -> u64 {
        (offset + self.bucket_size - 1) / self.bucket_size
    }
}

impl BCacheCache {
    fn make_cache_lookup_for(&self, dev: u32, keys: &[BKey], lookup: &mut HashMap<u64, BPtr>) {
        for k in keys {
            if dev != k.key.inode() {
                continue;
            }
            let start = k.key.offset().as_bytes() - k.key.size().as_bytes();
            if k.key.size().as_bytes() % u64::from(self.block_size) != 0 {
                panic!("Written data is not divisible by block size {}", k.key.size().as_bytes());
            }
            for s in 0..k.key.size().as_bytes() / u64::from(self.block_size) {
                let offset = s * u64::from(self.block_size);
                let back_offset = start + offset;
                lookup.remove(&back_offset);
                if k.key.dirty() {
                    let mut ptr = k.ptrs[0];
                    let cache_offset = ptr.offset().as_bytes() + offset;
                    ptr.set_offset(Sector::from_byte_offset(cache_offset));
                    if lookup.insert(back_offset, ptr).is_some() {
                        panic!("Was able to insert at {}?", back_offset);
                    }
                }
            }
        }
    }

    fn make_cache_lookup_for_node(&self, dev: u32, node: &BTree, lookup: &mut HashMap<u64, BPtr>) {
        match &node.pointers {
            BTreeChild::Data(d) => self.make_cache_lookup_for(dev, d, lookup),
            BTreeChild::Children(nodes) => {
                for node in nodes {
                    self.make_cache_lookup_for_node(dev, node, lookup)
                }
            }
        }
    }

    pub fn make_cache_lookup(&self, dev: u32) -> HashMap<u64, BPtr> {
        let broot = self.root.as_ref().unwrap();

        let mut ret = HashMap::new();

        self.make_cache_lookup_for_node(dev, broot, &mut ret);
        self.make_cache_lookup_for(dev, &self.journal_log, &mut ret);

        ret
    }

    pub fn write_back_cache(&mut self, dev: &mut BCacheBacking) -> Result<()> {
        let uuids = self.uuids.as_ref().unwrap();
        let uuid = dev.sb.uuid;

        if self.sb.set_uuid != dev.sb.set_uuid {
            return Err(BCacheRecoveryError::WriteBackError(
                WriteBackErrorKind::DifferentSets(self.sb.set_uuid, dev.sb.set_uuid),
            ));
        }

        let dev_idx;
        if let Some(index) = uuids.iter().position(|q| q.uuid == uuid) {
            dev_idx = index;
        } else {
            return Err(BCacheRecoveryError::WriteBackError(
                WriteBackErrorKind::DeviceNotFound(dev.sb.uuid),
            ));
        }

        let lookup = self.make_cache_lookup(dev_idx.try_into()?);
        let mut buf = vec![0; self.block_size.into()];
        let buf = &mut buf[..];
        for (k, d) in lookup {
            if d.dev() != 0 {
                panic!("Non-zero dev pointer???");
            }
            if d.gen()
                != self.prio_entries[self.offset_to_bucket(d.offset().as_bytes()) as usize].gen
            {
                return Err(BCacheRecoveryError::WriteBackError(
                    WriteBackErrorKind::GensDisagree(
                        d.gen(),
                        self.prio_entries[(d.offset().as_bytes() / self.bucket_size) as usize].gen,
                    ),
                ));
            }
            self.backing_file
                .seek(io::SeekFrom::Start(d.offset().as_bytes()))?;
            self.backing_file.read_exact(buf)?;

            dev.backing_file.seek(io::SeekFrom::Start(k))?;
            dev.backing_file.write_all(buf)?;
        }
        dev.backing_file.flush()?;

        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct BCacheBacking {
    pub sb: BCacheSB,
    pub data_offset: u64,
    pub flags: BackingFlags,
    #[serde(skip_serializing)]
    backing_file: File,
}

impl BCacheBacking {
    fn new(sb: BCacheSB, backing_file: File) -> Result<BCacheBacking> {
        Ok(BCacheBacking {
            data_offset: 16,
            flags: sb.flags.into(),
            sb,
            backing_file,
        })
    }
}

#[derive(Debug, Serialize)]
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
        drop(f);
        let f = OpenOptions::new().read(true).write(true).open(path)?;
        BCacheDev::Backing(BCacheBacking::new(sb, f)?)
    })
}
