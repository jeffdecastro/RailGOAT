# frozen_string_literal: true
require "encryption"

class User < ApplicationRecord
  attr_accessor :password

  validates :password, :presence => true,
                        :confirmation => true,
                        :if => :password,
                        :format => {:with => /\A.*(?=.{10,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\@\#\$\%\^\&\+\=]).*\z/}

    validates_presence_of :email
    validates_uniqueness_of :email
    validates_format_of :email, with: /.+@.+\..+/i

    has_one :retirement, dependent: :destroy
    has_one :paid_time_off, dependent: :destroy
    has_one :work_info, dependent: :destroy
    has_many :performance, dependent: :destroy
    has_many :pay, dependent: :destroy
    has_many :messages, foreign_key: :receiver_id, dependent: :destroy

    before_save :hash_password
    after_create { generate_token(:auth_token) }
    before_create :build_benefits_data

    def build_benefits_data
      build_retirement(POPULATE_RETIREMENTS.shuffle.first)
      build_paid_time_off(POPULATE_PAID_TIME_OFF.shuffle.first).schedule.build(POPULATE_SCHEDULE.shuffle.first)
      build_work_info(POPULATE_WORK_INFO.shuffle.first)
      # Uncomment below line to use encrypted SSN(s)
      # aes-256-cbc requires exactly a 16-byte IV; SecureRandom.hex(n) returns
      # a string of 2n bytes (hex-encoded), so this must be hex(8), not hex(32).
      work_info.build_key_management(:iv => SecureRandom.hex(8))
      performance.build(POPULATE_PERFORMANCE.shuffle.first)
    end

    def full_name
      "#{self.first_name} #{self.last_name}"
    end

    private

    def self.authenticate(email, password)
      user = find_by_email(email) || User.new(:password => "")
      if Rack::Utils.secure_compare(user.password_hash.to_s, Digest::MD5.hexdigest(password))
        return user
      else
        raise "Incorrect username or password"
      end
    end

    def hash_password
      if password.present?
        self.password_hash = Digest::MD5.hexdigest(password)
      end
    end

    def generate_token(column)
      loop do
        self[column] = Encryption.encrypt_sensitive_value(self.id)
        break unless User.exists?(column => self[column])
      end

      def as_json
        super(only: [:id, :email, :first_name, :last_name])
      end

      self.save!
    end
  end
