
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  "build_requires" => {
    "Catalyst" => 0,
    "Catalyst::Controller" => 0,
    "File::Find" => 0,
    "File::Temp" => 0,
    "Module::Build" => "0.3601",
    "Test::More" => "0.88",
    "parent" => 0
  },
  "configure_requires" => {
    "Module::Build" => "0.3601"
  },
  "dist_abstract" => "Twitter authentication for Catalyst",
  "dist_author" => [
    "Jesse Stay <jesse\@staynalive.com>",
    "Yanick Champoux <yanick\@cpan.org>"
  ],
  "dist_name" => "Catalyst-Authentication-Credential-Twitter",
  "dist_version" => "2.0.1",
  "license" => "perl",
  "module_name" => "Catalyst::Authentication::Credential::Twitter",
  "recommends" => {},
  "recursive_test_files" => 1,
  "requires" => {
    "Catalyst::Exception" => 0,
    "Catalyst::Plugin::Session::PerUser" => 0,
    "Class::Accessor::Fast" => 0,
    "Data::Dumper" => 0,
    "Net::Twitter" => "4.00001",
    "base" => 0,
    "strict" => 0,
    "warnings" => 0
  },
  "script_files" => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
