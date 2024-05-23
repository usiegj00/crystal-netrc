# netrc

A simple library to read and write `.netrc` files based on autocompletion from AI.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  netrc:
    github: usiegj00/crystal-netrc
```

## Usage

Write:
```crystal
user_netrc = Netrc.read
user_netrc["some.host.name"]  = {"email", "password"}
user_netrc.save
```

Read:
```crystal
user_netrc = Netrc.read
puts user_netrc.unparse
ent = user_netrc["some.host.name"]
exit if ent.nil?
puts ent.password
```

## Contributing

1. Fork it (<https://github.com/your-github-user/netrc/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [usiegj00](https://github.com/usiegj00) - creator and maintainer

## Copyright

Copyright 2024 usiegj00. All rights reserved.
