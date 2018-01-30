# encoding: utf-8
require 'test/logstash-filters/filter_test_helpers'

describe "platform.conf" do

  before(:all) do
    load_filters <<-CONFIG
      filter {
        #{File.read("src/logstash-filters/snippets/platform.conf")}
      }
    CONFIG
  end

  describe "#if" do

    describe "passed" do
      when_parsing_log(
          "@index_type" => "platform", # good value
          "@message" => "Some message"
      ) do

        # tag set => 'if' succeeded
        it { expect(subject["tags"]).to include "platform" }

      end
    end

    describe "failed" do
      when_parsing_log(
          "@index_type" => "some value", # bad value
          "@message" => "Some message"
      ) do

        # no tags set => 'if' failed
        it { expect(subject["tags"]).to be_nil }

        it { expect(subject["@index_type"]).to eq "some value" } # keeps unchanged
        it { expect(subject["@message"]).to eq "Some message" } # keeps unchanged

      end
    end

  end

  # -- general case
  describe "#fields when message is" do

    context "CF format (metron agent)" do
      when_parsing_log(
          "@index_type" => "platform",
          "@message" => "[job=nfs_z1 index=0]   Some message" # CF metron agent format
      ) do

        it { expect(subject["tags"]).to eq ["platform", "cf"] } # no fail tag

        it { expect(subject["@source"]["type"]).to eq "cf" }
        it { expect(subject["@type"]).to eq "cf" }

        it "sets grok fields" do
          expect(subject["@message"]).to eq "Some message"
          expect(subject["@source"]["job"]).to eq "nfs_z1"
          expect(subject["@source"]["instance"]).to eq "0"
        end

      end
    end

    context "CF format (syslog release)" do
      when_parsing_log(
          "@index_type" => "platform",
          "@message" => "[bosh instance=cf_full/nfs_z1/abcdefg123]   Some message" # CF syslog release format
      ) do

        it { expect(subject["tags"]).to eq ["platform", "cf"] } # no fail tag

        it { expect(subject["@source"]["type"]).to eq "cf" }
        it { expect(subject["@type"]).to eq "cf" }

        it "sets grok fields" do
          expect(subject["@message"]).to eq "Some message"
          expect(subject["@source"]["deployment"]).to eq "cf_full"
          expect(subject["@source"]["job"]).to eq "nfs_z1"
          expect(subject["@source"]["instance"]).to be_nil
        end

      end
    end

    context "RFC 5424 format and enterprise number is CF" do
      when_parsing_log(
          "@index_type" => "platform",
          "@message" => "Some message",
          "syslog_sd_id" => "instance@47450",
          "syslog_sd_params" => {
            "az" => "az1",
            "deployment" => "deployment1",
            "director" => "director1",
            "group" => "group1",
            "id" => "id1",
          },
      ) do

        it { expect(subject["tags"]).to eq ["platform", "cf"] } # no fail tag

        it { expect(subject["@source"]["type"]).to eq "cf" }
        it { expect(subject["@type"]).to eq "cf" }

        it "sets the common fields" do
          expect(subject["@message"]).to eq "Some message"
          expect(subject["@source"]["az"]).to eq "az1"
          expect(subject["@source"]["deployment"]).to eq "deployment1"
          expect(subject["@source"]["director"]).to eq "director1"
          expect(subject["@source"]["id"]).to eq "id1"
          expect(subject["@source"]["job"]).to eq "group1"
        end
      end
    end

    context "not CF format" do
      when_parsing_log(
          "@index_type" => "platform",
          "@message" => "Some message that fails grok" # bad format
      ) do

        # get parsing error
        it { expect(subject["tags"]).to eq ["platform", "fail/cloudfoundry/platform/grok"] }

        # no fields set
        it { expect(subject["@message"]).to eq "Some message that fails grok" } # keeps the same
        it { expect(subject["@index_type"]).to eq "platform" } # keeps the same
        it { expect(subject["@source"]["type"]).to eq "system" }
        it { expect(subject["@type"]).to be_nil }

      end
    end

  end

end
