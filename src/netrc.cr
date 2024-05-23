# TODO: Write documentation for `Netrc`
require "io/console"
require "process"

class Netrc
  VERSION = "0.11.0"

  # See http://stackoverflow.com/questions/4871309/what-is-the-correct-way-to-detect-if-ruby-is-running-on-windows
  WINDOWS = {% if flag?(:win32) %}true{% else %}false{% end %}
  CYGWIN  = false

  def self.default_path
    # Check that the key NETRC exists in the ENV hash
    if !ENV.has_key?("NETRC")
      File.join(home_path, netrc_filename)
    elsif File.directory?(ENV["NETRC"])
      # Backward compatible behavior where `[\._]netrc` gets appended to the `NETRC` env var if it points to a directory
      File.join(ENV["NETRC"], netrc_filename)
    else
      # Behavior identical to GNU inetutils where `NETRC` env var used as is.
      # See https://github.com/guillemj/inetutils/blob/master/ftp/ruserpass.c#L120-L132 for more info
      ENV["NETRC"]
    end
  end

  def self.home_path
    Path.home
  end

  def self.netrc_filename
    WINDOWS && !CYGWIN ? "_netrc" : ".netrc"
  end

  def self.config
    @@config ||= {} of String => String
  end

  def self.configure
    yield(config) if block_given?
    config
  end

  def self.check_permissions(path)
    perm = File.info(path).permissions.to_i & 0o777
    # perm = File.stat(path).mode & 0o777

    unless File.readable?(path)
      raise Error.new("File '#{path}' is not readable; perms are #{perm.to_s(8)}")
    end

    if perm != 0o400 && perm != 0o600 && !WINDOWS && !Netrc.config["allow_permissive_netrc_file"]
      raise Error.new("Permission bits for '#{path}' should be 0600 (or 0400), but are #{perm.to_s(8)}")
    end
  end

  def self.read(path = default_path)
    check_permissions(path)
    data = if path.ends_with?(".gpg")
      decrypted = if ENV["GPG_AGENT_INFO"]
        %x(gpg --batch --quiet --decrypt #{path})
      else
        print "Enter passphrase for #{path}: "
        STDIN.noecho do
          %x(gpg --batch --passphrase-fd 0 --quiet --decrypt #{path})
        end
      end
      if $? == 0
        decrypted
      else
        raise Error.new("Decrypting #{path} failed.") unless $? == 0
      end
    else
      File.read(path)
    end
    raise Error.new("File '#{path}' is empty") unless data
    # puts "-" * 80
    # puts data.lines.inspect
    # puts "-" * 80
    new(path, parse(lex(data.lines.to_a)))
  rescue e : File::NotFoundError
    new(path, parse(lex([] of String)))
  end

  class TokenArray < Array(String)
    def take
      if size < 1
        raise Error.new("unexpected EOF")
      end
      shift
    end

    def readto
      l = [] of String
      while size > 0 && !yield self[0]
        l << shift
      end
      l.join
    end
  end

  def self.lex(lines : Array(String))
    tokens = TokenArray.new
    lines.each do |line|
      parts = line.split(/(\s*#.*)/m)
      content = parts[0] + "\n" # Crystal READ strips the newlines...
      comment = parts.size > 1 ? parts[1] : ""
      content.each_char do |char|
        # puts char.ord
        case char.to_s
        when /\s/
          # puts "Space #{char}"
          if tokens.any? && tokens.last.ends_with?(/\s/)
            tokens[-1] += char.to_s
          else
            tokens << char.to_s
          end
        else
          # puts "Char"
          if tokens.any? && tokens.last.ends_with?(/\S/)
            tokens[-1] += char.to_s
          else
            tokens << char.to_s
          end
        end
      end
      tokens << comment unless comment.empty?
    end
    tokens
  end

  def self.skip?(s)
    s =~ /^\s/
  end

  def self.parse(ts : TokenArray) : Tuple(String, Array(Array(String)))
    # puts "#" * 80
    # puts ts.inspect
    # puts "#" * 80
    cur, item = [] of String, [] of Array(String)

    pre = ts.readto { |t| t == "machine" || t == "default" }

    while ts.size > 0
      if ts[0] == "default"
        cur << ts.take
        cur << ""
      else
        cur << ts.take + ts.readto { |t| !skip?(t) }
        cur << ts.take
      end

      login = [] of String
      password = [] of String

      2.times do
        t1 = ts.readto { |t| t == "login" || t == "password" || t == "machine" || t == "default" }

        if ts[0] == "login"
          login = [t1 + ts.take + ts.readto { |t| !skip?(t) }, ts.take]
        elsif ts[0] == "password"
          password = [t1 + ts.take + ts.readto { |t| !skip?(t) }, ts.take]
        else
          ts.unshift(t1)
        end
      end
      raise Error.new("machine entry without login or password") if login.nil? || password.nil?

      cur += login
      cur += password
      cur << ts.readto { |t| t == "machine" || t == "default" }

      item << cur
      cur = [] of String
    end

    {pre, item}
  end

  def initialize(path : String, data : Tuple(String, Array(Array(String))))
    @new_item_prefix = ""
    @path = path
    @pre, @payload = data # pre is the header, payload is the data

    @default = [] of String
    if @payload && @payload.any? && @payload.last[0] == "default"
      @default = @payload.pop
    end
  end

  property new_item_prefix : String

  class Entry
    property login : String
    property password : String
    def initialize(login : String, password : String)
      @login = login
      @password = password
    end
  end

  def [](k : String)
    # puts @payload.inspect
    if item = @payload.find { |datum| datum[1] == k }
      Entry.new(item[3], item[5])
    elsif @default.size > 5
      Entry.new(@default[3], @default[5])
    end
  end

  def []=(k : String, info : Tuple(String, String))
    if item = @payload.find { |datum| datum[1] == k }
      item[3], item[5] = info
    else
      @payload << new_item(k, info[0], info[1])
    end
  end

  def length
    @payload.size
  end

  def delete(key : String)
    datum = @payload.find { |value| value[1] == key }
    @payload.delete(datum) if datum
  end

  def each(&block)
    @payload.each(&block)
  end

  def new_item(m : String, l : String, p : String)
    [new_item_prefix + "machine ", m, "\n  login ", l, "\n  password ", p, "\n"]
  end

  def save
    # puts @path
    if @path.ends_with?(".gpg")
      e = Process.run("gpg -a --batch --default-recipient-self -e", output: :pipe) do |process|
        process.input.puts(unparse)
        process.wait
        process.output.gets_to_end
      end
      raise Error.new("Encrypting #{@path} failed.") unless $? == 0
      File.open(@path, "w", 0o600) { |file| file.print(e) }
    else
      File.open(@path, "w", 0o600) { |file| file.print(unparse) }
    end
  end

  def unparse
    @pre + @payload.map do |datum|
      datum = datum.join
      datum.ends_with?("\n") ? datum : datum + "\n"
    end.join
  end

end

class Netrc::Error < Exception
end

