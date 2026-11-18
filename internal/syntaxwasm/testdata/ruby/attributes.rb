# Methods made by calls, and names written with their scope.
module Billing
  module Ledgers; end
end

class Billing::Invoice
  attr_reader :number, :total
  attr_writer :note
  attr_accessor "status"
  private attr_reader :secret

  define_method(:paid?) { status == "paid" }
  define_method("void!") do
    self.status = "void"
    notify(:voided)
  end
  define_method("#{prefix}_amount") { total }

  alias_method :amount, :total
  alias :to_s :number

  protected

  attr_reader :audit_trail
end

module Billing::Ledgers::Export
  FORMAT = "csv"
  Billing::Ledgers::DEFAULT = :csv
end
