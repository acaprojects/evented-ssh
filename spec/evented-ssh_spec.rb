require 'evented-ssh'

describe ::ESSH do
    it "should run exec! succesfully" do
        res = ""
        reactor.run { |reactor|
            con = nil
            begin
                con = ESSH.start('127.0.0.1', 'docker', port: 2222)
                res = con.exec!("uname -a")
            ensure
                con.close
            end
        }
        expect(res).to match(/linux/i)
    end

    it "should run exec! in a block succesfully" do
        res = ""
        reactor.run { |reactor|
            ESSH.start('127.0.0.1', 'docker', port: 2222) do |con|
                res = con.exec!("uname -a")
            end
        }
        expect(res).to match(/linux/i)
    end

    it "should run promise exec succesfully" do
        res = ""
        reactor.run { |reactor|
            ESSH.start('127.0.0.1', 'docker', port: 2222) do |con|
                con.p_exec!("uname -a").then do |result|
                    res = result
                end
            end
        }
        expect(res).to match(/linux/i)
    end

    it "should start using a promise" do
        res = ""
        reactor.run { |reactor|
            connection = nil

            # , :verbose => Logger::DEBUG
            ESSH.p_start('127.0.0.1', 'docker', port: 2222).then { |con|
                connection = con
                res = con.exec!("uname -a")
            }.finally { connection.close }
        }
        expect(res).to match(/linux/i)
    end
end
