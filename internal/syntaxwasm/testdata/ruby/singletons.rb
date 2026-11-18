# A singleton class of another object keeps that object as its owner.
class Registry
  OTHER = Object.new
  class << OTHER
    def ping
    end
  end

  class << self
    def create
    end
  end
end
