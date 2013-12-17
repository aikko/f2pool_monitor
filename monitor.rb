# -*- encoding : utf-8 -*-
require 'net/http'
require 'mail'
require 'json'

# == 配置
# interval              监控间隔
# user_name             鱼池用户名
# password              鱼池密码
# from_email            发送邮件地址
# from_email_password   发送邮件密码
# smtp_server           发送邮件smtp服务器地址
# smtp_port             发送邮件stmp服务器端口
# domain                发送邮件域名
# to_email              收报警邮件地址，多个以逗号分开 
# exception_to_email    监控程序出错时，收邮件地址
# threshold             当矿工平均速度低于多少是报警


CONFIG = {
    :interval => 10 * 60 ,
    :user_name => '****',
    :password => '*****',
    :from_email => 'from@example.com',
    :from_email_password => '*****',
    :smtp_server => 'smtp.example.com',
    :smtp_port => 25,
    :domian => 'example.com'
    :to_email => 'to1@example.com, to2@example.com, to3@example.com'            ,
    :exception_to_email => 'to1@example.com',
    :threshold => 500
}


module Log
  def self.info(action,content='')
    puts "[action: #{action}, content: #{content}, time: #{Time.now}]"
  end
end

module Notification
  class Email
    class << self
      def send(subject, body, to=nil)
        to = CONFIG[:to_email] unless to;
        options = {:address => CONFIG[:smtp_server], :port => CONFIG[:smtp_prot], :domain => CONFIG[:domain], :user_name => CONFIG[:from_email], :password => CONFIG[:from_email_password], :enable_starttls_auto => true, :openssl_verify_mode => 'none'}
        Mail.defaults { delivery_method :smtp, options }
        mail = Mail.new do
          from CONFIG[:from_email]
          to to
          subject subject
          body body
        end
        mail.deliver!
      rescue
      end
    end
  end
end

module Simulation
  class NeedLoginException < Exception
  end

  class HTTP
    def initialize
      @retry_times = 0;
    end

    class << self
      def get(path)
        @@instance ||= self.new
        @@instance.get(path)
      end
    end

    def get(path)
      uri = URI(path)
      url = "#{uri.path}?#{uri.query}"
      resp = http.get(url, headers)
      raise Simulation::NeedLoginException.new if resp.code == '302'
      resp
    rescue Simulation::NeedLoginException
      @cookie = nil
      @retry_times = @retry_times + 1;
      retry if @retry_times < 3
    end


    private
    def http
      @http ||= Net::HTTP.new('www.f2pool.com')
    end

    def headers
      {'Cookie' => cookie,
       'Accept' => '*/*',
       'Accept-Encoding' => 'gzip, deflate',
       'Accept-Language' => 'zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3',
       'Connection' => 'keep-alive',
       'Host' => 'www.f2pool.com',
       'Referer' => 'http://www.f2pool.com/user/worker?action=load',
       'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:25.0) Gecko/20100101 Firefox/25.0',
       'X-Requested-With' => 'XMLHttpRequest'
      }
    end

    def login_data
      email = CONFIG[:user_name]
      password = CONFIG[:password]
      "email=#{email}&password=#{password}"
    end

    def login
      Log.info 'login', 'get cookie'
      begin
        @cookie = http.post('/user/login', login_data).get_fields('Set-Cookie').select { |e|
          e.match(/s_id/)
        }.map { |e|
          e.split(/; /)[0]
        }.first
      rescue
      end
    end

    def cookie
      login unless @cookie
      return '' unless @cookie
      @cookie
    end
  end
end


module Mining
  class Worker
    attr_accessor :name
    attr_accessor :hash_rate
    attr_accessor :created_at
  end

  class Monitor

    class << self
      def start
        Log.info :monitor, :start
        @@instance ||= self.new
        @@running = true
        @@last_error_workers = []
        while @@running do
          begin
            result = Simulation::HTTP.get('http://www.f2pool.com/user/worker?action=load').body;
            @@instance.check result
          rescue Exception => e
            Log.info :error, e.message
            @@instance.notify_error '报警监控异常', e.message
          end
          sleep CONFIG[:interval]
        end
        Log.info :monitor, :end
      end

      def stop
        @@running = false
      end
    end

    def notify_error(subject, body, to=nil)
      to = CONFIG[:exception_to_email] unless to
      Notification::Email.send subject, body, to
    end

    def notify(error_workers)
      return unless error_workers
      return if error_workers.size <= 0
      body = ''
      error_workers.each do |ew|
        body += "Worker: #{ew.name}, Hash Rate: #{ew.hash_rate}\n"
      end
      Notification::Email.send '旷工停机报警', body, CONFIG[:to_email]
    end

    def check(result)
      Log.info :check, result['status']
      json = JSON.parse(result)
      error_workers = [];
      json['data'].each do |data|
        hash_rate = data['hashrate'].split(' ')[0].to_f;
        if hash_rate < CONFIG[:threshold]
          worker = Worker.new
          worker.name = data['worker_name']
          worker.hash_rate = data['hashrate']
          error_workers << worker
        end
      end
      same =  is_same_last?(error_workers);
      @@last_error_workers = error_workers;
      Log.info :same, same
      notify(error_workers) unless same
    end

    def last_contain?(worker)
      @@last_error_workers.each do |w|
        if(w.name == worker.name)
          return true
        end
      end
      false
    end

    def is_same_last?(error_workers)
      return false unless error_workers.size == @@last_error_workers.size
      same_count = 0
      error_workers.each do |worker|
        if last_contain? worker
          same_count = same_count + 1
        end
      end
      retrun false unless same_count == @@last_error_workers.size
      true
    end

  end
end

Mining::Monitor.start();
