fn main() {
    let mut args = std::env::args();
    args.next().expect("First argument");

    for file in args {
        println!("Reading {}", file);
        let dev = bcache_recovery::open_device(&file).expect("Couldn't read dev");

        match dev {
            bcache_recovery::BCacheDev::Cache(cdev) => {
                println!("{:?}", cdev);
                println!("{:?}", cdev.make_cache_lookup(0));
            }
            bcache_recovery::BCacheDev::Backing(bdev) => println!("{:?}", bdev),
        }
    }
}
