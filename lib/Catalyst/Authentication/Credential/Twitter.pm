package Catalyst::Authentication::Credential::Twitter;

use strict;
use warnings;
use base qw( Class::Accessor::Fast );
use Data::Dumper;

BEGIN {
    __PACKAGE__->mk_accessors(qw/
        _twitter twitter_user callback_url consumer_key consumer_secret
    /);
}

our $VERSION = '0.02001';

use Catalyst::Exception ();
use Net::Twitter;

sub new {
    my ($class, $config, $c, $realm) = @_;
    my $self = {};
    bless $self, $class;

    # Hack to make lookup of the configuration parameters less painful
    my $params = { %{ $config }, %{ $realm->{config} } };

	$params->{'consumer_key'} ||= $c->config->{'twitter_consumer_key'};
	$params->{'consumer_secret'} ||= $c->config->{'twitter_consumer_secret'};
	$params->{'callback_url'} ||= $c->config->{'twitter_callback_url'};
    # Check for required params (yes, nasty)
    for my $param (qw/consumer_key consumer_secret callback_url/) {
        $self->$param($params->{$param}) or
            Catalyst::Exception->throw("$param not defined") 
    }

    # Create a Net::Twitter instance
    $self->_twitter(Net::Twitter->new({ 
		'traits'        	=> ['API::REST', 'OAuth'],
		'consumer_key' 		=> $self->consumer_key, 
        'consumer_secret'	=> $self->consumer_secret,
	}));

    return $self;
}

sub authenticate_twitter {
    my ( $self, $c ) = @_;

	if (!$c->user_session->{'request_token'} || !$c->user_session->{'request_token_secret'} || !$c->req->params->{'oauth_verifier'}) {
		die 'no request token present, or no verifier';
	}

	my $token = $c->user_session->{'request_token'};
	my $token_secret = $c->user_session->{'request_token_secret'};
	my $verifier = $c->req->params->{'oauth_verifier'};
	my $access_token = $c->user_session->{'access_token'};
	my $access_token_secret = $c->user_session->{'access_token_secret'};

    # Create a Net::Twitter instance
    $self->_twitter(Net::Twitter->new({ 
		'traits'        	=> ['API::REST', 'OAuth'],
		'consumer_key' 		=> $self->consumer_key, 
        'consumer_secret'	=> $self->consumer_secret,
	}));

	if (!$access_token && !$access_token_secret) {
		$self->_twitter->request_token($token);
    	$self->_twitter->request_token_secret($token_secret);

		($access_token, $access_token_secret) = $self->_twitter->request_access_token('verifier' => $verifier);
		# this is in case we need to register the user after the oauth process
		$c->user_session->{'access_token'} = $access_token;
		$c->user_session->{'access_token_secret'} = $access_token_secret;
	}

	# get the user
	$self->_twitter->access_token($access_token);
    $self->_twitter->access_token_secret($access_token_secret);

	my $twitter_user_hash = eval {
		$self->_twitter->verify_credentials;
	};

	if ($@ || !$twitter_user_hash) {
		$c->log->debug("no twitter_user_hash or error: ".$@);
		return undef;
	}

	$twitter_user_hash->{'access_token'} = $access_token;
	$twitter_user_hash->{'access_token_secret'} = $access_token_secret;

    $self->twitter_user( $twitter_user_hash );

    return $twitter_user_hash;
}

sub authenticate {
    my ( $self, $c, $realm, $authinfo ) = @_;

	unless ($authinfo) {
        $self->authenticate_twitter( $c ) unless $self->twitter_user;

		$authinfo = {
			'twitter_user_id'	=> $self->twitter_user->{'id'},
		};
	}

    my $user_obj = $realm->find_user($authinfo, $c);

	if (ref $user_obj) {
		if ($user_obj->result_source->has_column('twitter_user') && $user_obj->result_source->has_column('twitter_access_token') && $user_obj->result_source->has_column('twitter_access_token_secret')) {
            my $twitter_user = $self->twitter_user;
			$user_obj->update({
				'twitter_user'					=> $twitter_user->{'screen_name'},
				'twitter_access_token'			=> $twitter_user->{access_token},
				'twitter_access_token_secret'	=> $twitter_user->{access_token_secret},
			});
		}
		return $user_obj;
	}

    return undef;
}
    
sub authenticate_twitter_url {
    my ($self, $c) = @_;

    # Create a Net::Twitter instance
    $self->_twitter(Net::Twitter->new( 
		'traits'        	=> ['API::REST', 'OAuth'],
		'consumer_key' 		=> $self->consumer_key, 
        'consumer_secret'	=> $self->consumer_secret,
	));

    my $uri = $self->_twitter->get_authorization_url( 'callback'	=> $c->config->{'twitter_callback_url'} || $self->callback_url );
	$c->user_session->{'request_token'} = $self->_twitter->request_token;
	$c->user_session->{'request_token_secret'} = $self->_twitter->request_token_secret;
	$c->user_session->{'access_token'} = '';
	$c->user_session->{'access_token_secret'} = '';

    return $uri;
}

=head1 NAME

Catalyst::Authentication::Credential::Twitter - Twitter authentication for Catalyst

=head1 SYNOPSIS

In MyApp.pm

 use Catalyst qw/
    Authentication
    Session
    Session::Store::FastMmap
    Session::State::Cookie
	Session::PerUser
 /;
 
 MyApp->config(
     "Plugin::Authentication" => {
         default_realm => "twitter",
         realms => {
             twitter => {
                 credential => {
                     class => "Twitter",
                 },

                 consumer_key    => 'twitter-consumer_key-here',
                 consumer_secret => 'twitter-secret-here',
                 callback_url => 'http://mysite.com/callback',
				 # you can bypass the above by including
				 # "twitter_consumer_key", "twitter_consumer_secret", 
				 # and "twitter_callback_url" in your Catalyst site
				 # configuration or yml file
             },
         },
     },
 );

And then in your Controller:

 sub login : Local {
    my ($self, $c) = @_;
    
    my $realm = $c->get_auth_realm('twitter');
    $c->res->redirect( $realm->credential->authenticate_twitter_url($c) );
 }

And finally the callback you specified in your API key request above (e.g.
example.com/twitter/callback/ ):

 sub callback : Local {
    my ($self, $c) = @_;
    
    if (my $user = $c->authenticate(undef,'twitter')) {
		# user has an account - redirect or do something cool
    	$c->res->redirect("/super/secret/member/area");
	}
	else {
		# user doesn't have an account - either detect Twitter
		# credentials and create one, or return an error.
		#
		# Note that "request_token" and "request_token_secret"
		# are stored in $c->user_session as hashref variables under
		# the same names
	}
 }

=head1 DESCRIPTION

This module handles Twitter API authentication in a Catalyst application.

=head1 METHODS

As per guidelines of L<Catalyst::Plugin::Authentication>, there are two
mandatory methods, C<new> and C<authenticate>. Since this is not really
enough for the Twitter API, I've added one more.

=head2 new()

Will not be called by you directly, but will use the configuration you
provide (see above). Mandatory parameters are C<consumer_key>, C<consumer_secret> and
C<callback_url>. Note that you can also include C<twitter_consumer_key>, C<twitter_consumer_secret>, and C<twitter_callback_url> as variables in your Catalyst site configuration or yml file and you don't need to pass configuration parameters in your MyApp.pm file.  Please see L<Net::Twitter> for more details on them.

=head2 authenticate_twitter_url( $c )

This method will return the authentication URL. Bounce your users there
before calling the C<authentication> method.

=head2 authenticate( )

Handles the authentication. Nothing more, nothing less. It returns
a L<Catalyst::Authentication::User::Hash> with the following keys
(all coming straight from Twitter).

=over 4

=item twitter_user

=item twitter_user_id

=item twitter_access_token

=item twitter_access_token_secret

=back

Your database must at least contain a column called "twitter_user_id"
in your main user table. If the other keys are present they will be
updated on login with Twitter's most up-to-date information for that
user.

=head2 authenticate_twitter( )

Only performs the twitter authentication. Returns a hashref containing
the user's information given by Twitter (see C<authenticate()> above for
the lists of keys returned).

=head2 twitter_user()

Contains the user's twitter information after a successful twitter
authentication via C<authenticate_twitter()> or
C<authenticate()>. Useful if, for example, you want to create users
on-the-fly:

    sub twitter_callback :Path( 'twitter/callback' ) {
        my ($self, $c) = @_;

        my $twitter = $c->get_auth_realm('twitter')->credential;
        my $user =  $twitter->authenticate( $c );

        # properly authenticated against twitter,
        # user just doesn't exist yet
        if ( !$user and  $twitter->twitter_user ) {
            $user = $self->model->create_user( $twitter->twitter_user );
        }

        # etc
    }

=head1 AUTHOR

Jesse Stay
E<lt>jesse@staynalive.comE<gt>
L<http://staynalive.com>

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.

=head1 SEE ALSO

L<Catalyst::Plugin::Authentication>, L<Net::Twitter>

=head1 BUGS

C<Bugs? Impossible!>. Please report bugs to L<http://rt.cpan.org/Ticket/Create.html?Queue=Catalyst-Authentication-Credential-Twitter>

=head1 THANKS

Thanks go out Daisuke Murase for writing C::P::A::Credential::Flickr,
Marc Mims and Chris Thompson for Net::Twitter.

=cut

1;
