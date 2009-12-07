use strict;
use Module::Build;

my %arguments = (
    create_makefile_pl => 'passthrough',
    license            => 'perl',
    module_name        => 'Catalyst::Authentication::Credential::Twitter',
    requires           => {
        'DBIx::Class'               			=> 0.06002,
        'Net::Twitter'       					=> "3.10001",
		'Catalyst::Plugin::Session::PerUser'	=> 0.04,
		'Catalyst'								=> 5.80007,
    },
    create_makefile_pl => 'passthrough',
    create_readme      => 1,
    test_files         => [ glob('t/*.t')]
);

Module::Build->new(%arguments)->create_build_script;
