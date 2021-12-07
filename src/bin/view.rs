use bcache_recovery::error::*;
use bcache_recovery::*;

fn main() -> std::result::Result<(), BCacheRecoveryError> {
    let mut args = std::env::args();
    args.next().expect("First argument");
    let dev = args.next().expect("No device?");

    let dev = open_device(&dev)?;

    //println!("{:?}", dev);
    println!("{}", serde_json::to_string_pretty(&dev).unwrap());
    if let BCacheDev::Cache(x) = dev {
        x.make_cache_lookup(0);
    }
    Ok(())
}
