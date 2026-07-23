# frozen_string_literal: true
if Rails.env.production?
  # Specify env variable/location/etc. to retrieve key from
elsif Rails.env.development? || Rails.env.test?
  # aes-256-cbc requires exactly a 32-byte key; the previous value here was
  # 45 bytes and made every SSN encryption raise ArgumentError.
  KEY = "12345678910111212345678910111212"
end
