# frozen_string_literal: true

require 'json'
require 'set'
require 'securerandom'
require_relative 'support/clock'
require_relative '../config/limits'
load 'tasks/maintenance.rb'
autoload :Metrics, 'job_queue/metrics'

$job_queue_booted = Time.now

module JobQueue
  VERSION = '2.4.0'
  DEFAULT_WORKERS = 4
  RETRY_LIMIT = 5

  class Error < StandardError; end
  class TimeoutError < Error; end
  class Rejected < ::JobQueue::Error
    def initialize(job, reason = 'rejected')
      super("#{job.id}: #{reason}")
      @job = job
    end

    attr_reader :job
  end

  Priority = Struct.new(:level, :label) do
    include Comparable

    def <=>(other)
      level <=> other.level
    end

    def to_s
      "#{label}(#{level})"
    end
  end

  Settings = Data.define(:workers, :timeout)
  Handler = Class.new(Object)
  Plugins = Module.new

  module Loggable
    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods
      def log_prefix(value = nil)
        @log_prefix = value if value
        @log_prefix || name
      end
    end

    def log(message)
      puts "[#{self.class.log_prefix}] #{message}"
    end

    module_function

    def timestamp
      Time.now.utc.iso8601
    end
  end

  module Retryable
    def with_retries(limit: RETRY_LIMIT)
      attempts = 0
      begin
        attempts += 1
        yield attempts
      rescue Rejected, JobQueue::TimeoutError => e
        retry if attempts < limit
        raise e
      end
    end
  end

  class Job
    include Comparable
    include Loggable
    extend Forwardable
    prepend Retryable

    attr_accessor :payload, :attempts
    attr_reader :id, :priority

    @@created = 0
    REGISTRY = {}

    class << self
      def create(payload, priority: 0)
        new(payload, priority: priority).tap { |job| REGISTRY[job.id] = job }
      end

      def created
        @@created
      end

      private

      def reset_counter
        @@created = 0
      end
    end

    def self.parse(text)
      data = JSON.parse(text)
      create(data.fetch('payload'), priority: data.fetch('priority', 0))
    end

    def self.build_all(items)
      items.map { |item| create(item) }
    end

    private_class_method :build_all

    def initialize(payload, priority: 0)
      @id = SecureRandom.uuid
      @payload = payload
      @priority = Priority.new(priority, 'normal')
      @attempts = 0
      @@created += 1
    end

    def <=>(other)
      priority <=> other.priority
    end

    def run(&block)
      with_retries do |attempt|
        log("attempt #{attempt}")
        block.call(self)
      end
    end

    def done?
      !result.nil?
    end

    def result=(value)
      @result = value
    end

    def to_h
      { id: id, payload: payload, attempts: attempts }
    end

    alias to_hash to_h
    alias_method :to_s, :inspect

    protected

    def merge_attempts(other)
      @attempts += other.attempts
    end

    private

    def cleanup
      REGISTRY.delete(id)
    end

    def audit
      Metrics.record(self)
    end

    public

    def summary
      "#{id[0, 8]} #{payload.inspect}"
    end

    private def internal_flag
      true
    end

    def exposed_flag = false
    private :exposed_flag

    def self.registry_size = REGISTRY.size
  end

  class Queue
    include Enumerable
    include JobQueue::Loggable

    attr_reader :jobs

    def initialize(workers: DEFAULT_WORKERS, clock: Clock.new)
      @jobs = []
      @workers = workers
      @clock = clock
      @lock = Mutex.new
    end

    def push(job)
      raise Rejected.new(job, 'closed') if closed?

      @lock.synchronize do
        @jobs << job
        @jobs.sort!
      end
      job
    end
    alias << push

    def pop
      @lock.synchronize { @jobs.shift }
    end

    def each(&block)
      return enum_for(:each) unless block

      @jobs.each(&block)
      self
    end

    def drain(handler)
      until empty?
        job = pop
        handler.call(job)
      end
    rescue Rejected => e
      log("drain failed: #{e.message}")
    ensure
      log('drain finished')
    end

    def empty?
      @jobs.empty?
    end

    def closed?
      @closed ||= false
    end

    def close
      @closed = true
    end

    def stats
      Stats.new(@jobs.size, @workers)
    end

    class Stats
      attr_reader :size, :workers

      def initialize(size, workers)
        @size = size
        @workers = workers
      end

      def busy?
        size > workers
      end
    end
  end

  class Worker < Thread
    def self.start(queue, handler)
      new(queue, handler)
    end

    def initialize(queue, handler)
      @queue = queue
      @handler = handler
      super() { work }
    end

    def work
      loop do
        job = @queue.pop or break
        @handler.call(job)
      end
    end
  end

  class Scheduler
    DEFAULTS = { workers: DEFAULT_WORKERS, timeout: 30 }.freeze

    def initialize(queue, **options)
      @queue = queue
      @settings = Settings.new(**DEFAULTS.merge(options))
      @workers = []
    end

    def run(handler = Handler.new)
      @settings.workers.times do
        @workers << Worker.start(@queue, handler)
      end
      @workers.each(&:join)
    end

    def stop
      @queue.close
      @workers.each(&:kill)
    end
  end
end

module JobQueue::Testing
  FakeJob = Struct.new(:id, :payload)

  def self.fake(payload)
    FakeJob.new(SecureRandom.hex(4), payload)
  end
end

class JobQueue::Runner < JobQueue::Scheduler
  def run(handler = nil)
    super(handler || ->(job) { job.run { |j| puts j.summary } })
  end
end

def run_queue(items)
  queue = JobQueue::Queue.new
  items.each { |item| queue.push(JobQueue::Job.create(item)) }
  JobQueue::Scheduler.new(queue).run
  queue.stats
end

if $PROGRAM_NAME == __FILE__
  stats = run_queue(ARGV)
  puts stats.size
end
