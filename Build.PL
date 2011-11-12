
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  "build_requires" => {
    "Carp" => 0,
    "Catalyst" => 0,
    "Catalyst::Controller" => 0,
    "Module::Build" => "0.3601",
    "Scalar::Util" => 0,
    "Test::More" => "0.94",
    "parent" => 0,
    "perl" => "5.004"
  },
  "configure_requires" => {
    "Module::Build" => "0.3601"
  },
  "dist_abstract" => "Twitter authentication for Catalyst",
  "dist_author" => [
    "Jesse Stay <jesse\@staynalive.com>"
  ],
  "dist_name" => "Catalyst-Authentication-Credential-Twitter",
  "dist_version" => "0.02002",
  "license" => "perl",
  "module_name" => "Catalyst::Authentication::Credential::Twitter",
  "recommends" => {},
  "recursive_test_files" => 1,
  "requires" => {
    "Catalyst::Exception" => 0,
    "Class::Accessor::Fast" => 0,
    "Data::Dumper" => 0,
    "Net::Twitter" => 0,
    "base" => 0,
    "strict" => 0,
    "warnings" => 0
  },
  "script_files" => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
