use bcache_recovery::error::*;
use bcache_recovery::*;

fn main() -> Result<(), BCacheRecoveryError> {
    let mut args = std::env::args();
    args.next().expect("First argument");
    let cache = args.next().expect("No cache device?");
    let back = args.next().expect("No backing device?");
    let mut cache = match open_device(&cache)? {
        bcache_recovery::BCacheDev::Cache(cache) => cache,
        _ => panic!("Non-cache device given as cache."),
    };
    let mut back = match open_device(&back)? {
        bcache_recovery::BCacheDev::Backing(back) => back,
        _ => panic!("Non-backing device given as backing device."),
    };

    cache.write_back_cache(&mut back)
}
