package Apache::Htpasswd;

# $Id: Htpasswd.pm,v 1.4 2001/02/23 08:23:46 kevin Exp kevin $
# $Log: Htpasswd.pm,v $

# Revision 1.4  2001/02/23 08:23:46 kevin
# Added support for extra info fields

# Revision 1.3  2000/04/04 15:00:15 meltzek
# Made file locking safer to avoid race conditions. Fixed
# typo in docs.  

# Revision 1.2  1999/01/28 22:43:45  meltzek
# Added slightly more verbose error croaks. Made sure error from htCheckPassword is only called when called directly, and not by $self.
#
# Revision 1.1  1998/10/22 03:12:08  meltzek
# Slightly changed how files lock.
# Made more use out of carp and croak.
# Made sure there were no ^M's as per Randal Schwartz's request.
#
# Revision 1.0  1998/10/21 05:53:56  meltzek
# First version on CPAN.
#


use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use strict;		# Restrict unsafe variables, references, barewords
use Carp;

use POSIX qw ( SEEK_SET SEEK_END );
use Fcntl qw ( LOCK_EX LOCK_UN );

@ISA = qw(Exporter);

@EXPORT = qw();

@EXPORT_OK = qw(htpasswd htDelete fetchPass fetchInfo writeInfo htCheckPassword error Version);

%EXPORT_TAGS = (all => [@EXPORT_OK]);

($VERSION = substr(q$Revision: 1.4 $, 10)) =~ s/\s+$//;

sub Version {
	return $VERSION;
}

#-----------------------------------------------------------#
# Public Methods
#-----------------------------------------------------------#

sub new {
	my ($proto, $passwdFile) = @_;

	my $class = ref($proto) || $proto;
	my ($self) = {};
	bless ($self, $class);

	$self->{'PASSWD'} = $passwdFile;
	$self->{'ERROR'} = "";
	$self->{'LOCK'} = 0;
	$self->{'OPEN'} = 0;
	
	return $self;
}

#-----------------------------------------------------------#

sub error {
	my ($self) = @_;
	return $self->{'ERROR'};
}

#-----------------------------------------------------------#

sub htCheckPassword {
	my ($self) = shift;
	my ($Id, $pass) = @_;

	my ($cryptPass) = $self->fetchPass($Id);

	if (!$cryptPass) { return undef; }

	my ($fooCryptPass) = $self->CryptPasswd($pass, $cryptPass);

	if ($fooCryptPass eq $cryptPass) {
		return 1;
	} else {
		$self->{'ERROR'} = __PACKAGE__."::htCheckPassword - Passwords do not match.";
		carp $self->error() unless caller ne $self;
		return 0;
	}
}

#-----------------------------------------------------------#

sub htpasswd {
	my ($self) = shift;
	my ($Id) = shift;
	my ($newPass) = shift;
	my ($oldPass) = @_ if (@_);
	my ($noOld)=0;

	if (!defined($oldPass)) { $noOld=1;}
	if (defined($oldPass) && $oldPass =~ /^\d$/) {
		if ($oldPass) {
			$newPass = $Id unless $newPass;
			my ($newEncrypted) = $self->CryptPasswd($newPass);
			return $self->writePassword($Id, $newEncrypted);
		}
	}

	# New Entry
	if ($noOld) {
	    my ($passwdFile) = $self->{'PASSWD'};

		# Encrypt new password string

		my ($passwordCrypted) = $self->CryptPasswd($newPass);

    		$self->_open();

		if ($self->fetchPass($Id)) {

			# User already has a password in the file. 
			$self->{'ERROR'} = __PACKAGE__. "::htpasswd - $Id already exists in $passwdFile";
			carp $self->error();

			$self->_close();  
			return undef;
		} else {
			# If we can add the user.
	
	    		seek(FH, 0, SEEK_END);
	    		print FH "$Id\:$passwordCrypted\n";
	    
	    		$self->_close();  
	    		return 1;
		}

    		$self->_close();

	} else {
    		$self->_open();

		my ($exists) = $self->htCheckPassword($Id, $oldPass);

		if ($exists) {
			my ($newCrypted) = $self->CryptPasswd($newPass);
			return $self->writePassword($Id, $newCrypted);
		} else {
			# ERROR returned from htCheckPass
			$self->{'ERROR'} = __PACKAGE__."::htpasswd - Password not changed.";
			carp $self->error();
			return undef;
		}

    		$self->_close();
    	}
} # end htpasswd

#-----------------------------------------------------------#

sub htDelete {
	my ($self, $Id) = @_;
	my ($passwdFile) = $self->{'PASSWD'};
	my (@cache);
	my ($return);

	# Loop through the file, building a cache of exising records
	# which don't match the Id.

	$self->_open();

	seek(FH, 0, SEEK_SET);
	while (<FH>) {

		if (/^$Id\:/) {
			$return = 1; 
		} else {
			push(@cache, $_);
		}
	}


	# Write out the @cache if needed.

	if ($return) {

	    # Return to beginning of file
	    seek(FH, 0, SEEK_SET);
	    
	    while (@cache) { 
		print FH shift (@cache); 
	    }

	    # Cut everything beyond current position
	    truncate(FH, tell(FH));

	} else {
	    $self->{'ERROR'} = __PACKAGE__. "::htDelete - User $Id not found in $passwdFile: $!";
	    carp $self->error();
	}

	$self->_close();

	return $return;
}

#-----------------------------------------------------------#

sub fetchPass {
	my ($self) = shift;
	my ($Id) = @_;
	my ($passwdFile) = $self->{'PASSWD'};

	my $passwd = 0;

	$self->_open();
	
	while (<FH>) {
		chop;
		my @tmp = split(/:/,$_,3);
		if ( $tmp[0] eq $Id ) {
		    $passwd = $tmp[1];
		    last;
		}
	}

	$self->_close();

	return $passwd;
}

#-----------------------------------------------------------#

sub writePassword {
	my ($self) = shift;
	my ($Id, $newPass) = @_;

	my ($passwdFile) = $self->{'PASSWD'};
	my (@cache);

	my ($return);
	
	$self->_open();
	seek(FH, 0, SEEK_SET);

	while (<FH>) {

	    my @tmp = split(/:/,$_,3);
	    if ( $tmp[0] eq $Id ) {
		my $info = $tmp[2] ? $tmp[2] : "";
	        push (@cache, "$Id\:$newPass\:$info");
	        $return = 1; 

	    } else {
	        push (@cache, $_);
	    }
	}

	# Write out the @cache, if needed.

	if ($return) {
	    
	    # Return to beginning of file
	    seek(FH, 0, SEEK_SET);

		while (@cache) { 
			print FH shift (@cache); 
		}

	    # Cut everything beyond current position
	    truncate(FH, tell(FH));

	} else {
		$self->{'ERROR'} = __PACKAGE__. "::writePassword - User $Id not found in $passwdFile: $!";
		carp $self->error() . "\n";
	}

	$self->_close();

	return $return;
}

#-----------------------------------------------------------#

sub fetchInfo {
	my ($self) = shift;
	my ($Id) = @_;
	my ($passwdFile) = $self->{'PASSWD'};

	my $info = 0;

	$self->_open();
	
	while (<FH>) {
		chop;
		my @tmp = split(/:/,$_,3);
		if ( $tmp[0] eq $Id ) {
		    $info = $tmp[2];
		    last;
		}
	}

	$self->_close();

	return $info;
}

#-----------------------------------------------------------#

sub writeInfo {
	my ($self) = shift;
	my ($Id, $newInfo) = @_;

	my ($passwdFile) = $self->{'PASSWD'};
	my (@cache);

	my ($return);
	
	$self->_open();
	seek(FH, 0, SEEK_SET);

	while (<FH>) {

        my @tmp = split(/:/,$_,3);
		if ( $tmp[0] eq $Id ) {
			push (@cache, "$Id\:$tmp[1]\:$newInfo\n");
			$return = 1; 

		} else {
			push (@cache, $_);
		}
	}

	# Write out the @cache, if needed.

	if ($return) {
	    
	    # Return to beginning of file
	    seek(FH, 0, SEEK_SET);

		while (@cache) { 
			print FH shift (@cache); 
		}

	    # Cut everything beyond current position
	    truncate(FH, tell(FH));

	} else {
		$self->{'ERROR'} = __PACKAGE__. "::writeInfo - User $Id not found in $passwdFile: $!";
		carp $self->error() . "\n";
	}

	$self->_close();

	return $return;
}

#-----------------------------------------------------------#

sub CryptPasswd {
	my ($self) = shift;
	my ($passwd, $salt) = @_;

	if ($salt) {
		# Make sure only use 2 chars
		$salt = substr ($salt, 0, 2);
	} else {
		$salt = substr ($0, 0, 2);
	}

	return crypt ($passwd, $salt);
}

#-----------------------------------------------------------#

sub DESTROY { close(FH); };

#-----------------------------------------------------------#

    sub _lock {
	my ($self) = shift;
	
	# Lock if we don't have the lock
        flock(FH, LOCK_EX) if($self->{'LOCK'} == 0);

	# We have the lock
	$self->{'LOCK'} = 1;

	# Seek to head
        seek(FH, 0, SEEK_SET);
    }

#-----------------------------------------------------------#

    sub _unlock {
	my ($self) = shift;

        flock(FH, LOCK_UN);

	$self->{'LOCK'} = 0;
    }

#-----------------------------------------------------------#

sub _open {
    my ($self) = shift;

    if($self->{'OPEN'} > 0) {
	$self->{'OPEN'}++;
	$self->_lock();
	return;
    }

    my $passwdFile = $self->{'PASSWD'};
    if (!open(FH,"+<$passwdFile")) {
	$self->{'ERROR'} = __PACKAGE__. "::fetchPass - Cannot open $passwdFile: $!";
	croak $self->error();
    }

    $self->{'OPEN'}++;
    $self->_lock();
}

#-----------------------------------------------------------#

sub _close {
    my ($self) = shift;
    $self->_unlock();

    $self->{'OPEN'}--;

    if($self->{'OPEN'} > 0) { return; }

    if (!close(FH)) {
	my $passwdFile = $self->{'PASSWD'};
	$self->{'ERROR'} = __PACKAGE__. "::htDelete - Cannot close $passwdFile: $!";
	carp $self->error();
	return undef;
    }


}

#-----------------------------------------------------------#

1; 

__END__

=head1 NAME

Apache::Htpasswd - Manage Unix crypt-style password file.

=head1 SYNOPSIS

    use Apache::Htpasswd;

    $foo = new Apache::Htpasswd("path-to-file");

    # Add an entry    
    $foo->htpasswd("zog", "password");

    # Change a password    
    $foo->htpasswd("zog", "new-password", "old-password");
    
    # Change a password without checking against old password
    # The 1 signals that the change is being forced.
    
    $foo->htpasswd("zog", "new-password", 1);
        
    # Check that a password is correct
    $pwdFile->htCheckPassword("zog", "password");

    # Fetch an encrypted password 
    $foo->fetchPass("foo");
    
    # Delete entry
    $foo->htDelete("foo");

    # If something fails, check error
    $foo->error;

    # Write in the extra info field
    $foo->writeInfo("login", "info");

    # Get extra info field for a user
    $foo->fetchInfo("login");

=head1 DESCRIPTION

This module comes with a set of methods to use with htaccess password
files. These files (and htaccess) are used to do Basic Authentication
on a web server.

The passwords file is a flat-file with login name and their associated
crypted password. You can use this for non-Apache files if you wish, but
it was written specifically for .htaccess style files.

=head2 FUNCTIONS

=over 4

=item htaccess->new("path-to-file");

"path-to-file" should be the path and name of the file containing
the login/password information.


=item error;

If a method returns an error, or a method fails, the error can
be retrived by calling error()


=item htCheckPassword("login", "password");

Finds if the password is valid for the given login.

Returns 1 if passes.
Returns 0 if fails.


=item htpasswd("login", "password");

This will add a new user to the password file.
Returns 1 if succeeds.
Returns undef on failure.


=item htDelete("login")

Delete users entry in password file.

Returns 1 on success
Returns undef on failure.


=item htpasswd("login", "new-password", "old-password");

If the I<old-password> matches the I<login's> password, then
it will replace it with I<new-password>. If the I<old-password>
is not correct, will return 0.


=item htpasswd("login", "new-password", 1);

Will replace the password for the login. This will force the password
to be changed. It does no verification of old-passwords.

Returns 1 if succeeds
Returns undef if fails


=item fetchPassword("login");

Returns I<encrypted> password if succeeds.
Returns 0 if login is invalid.
Returns undef otherwise.


=item fetchInfo("login");

Returns additional information if succeeds.
Returns 0 if login is invalid.
Returns undef otherwise.


=item writeInfo("login", "info");

Will replace the additional information for the login.
Returns 0 if login is invalid.
Returns undef otherwise.


=item CryptPasswd("password", "salt");

Will return an encrypted password using 'crypt'. If I<salt> is
ommitted, a salt will be given by the subroutine using the first 2
character of $0.

=back

=head1 INSTALLATION

You install Apache::Htpasswd, as you would install any perl module library,
by running these commands:

   perl Makefile.PL
   make
   make test
   make install
   make clean

=head1 DOCUMENTATION

POD style documentation is included in the module.  
These are normally converted to manual pages and installed as part 
of the "make install" process.  You should also be able to use 
the 'perldoc' utility to extract and read documentation from the 
module files directly.


=head1 AVAILABILITY

The latest version of Apache::Htpasswd should always be available from:

    $CPAN/modules/by-authors/id/K/KM/KMELTZ/

Visit <URL:http://www.perl.com/CPAN/> to find a CPAN
site near you.

=head1 VERSION

$Revision: 1.3 $ $Date: 2000/04/04 15:00:13 $

=head1 CHANGES

$Log: Htpasswd.pm,v $

Revision 1.4  2001/02/23 08:23:46 kevin
Added support for extra info fields

Revision 1.3  2000/04/04 15:00:15 meltzek
Made file locking safer to avoid race conditions. Fixed
typo in docs.

Revision 1.2  1999/01/28 22:43:45  meltzek
Added slightly more verbose error croaks. Made sure error from htCheckPassword is only called when called directly, and not by $self.

Revision 1.1  1998/10/22 03:12:08  meltzek
Slightly changed how files lock.
Made more use out of carp and croak.
Made sure there were no ^M's as per Randal Schwartz's request.


=head1 BUGS

None knows at time of writting.

=head1 AUTHOR INFORMATION

Copyright 1998..2001, Kevin Meltzer.  All rights reserved.  It may
be used and modified freely, but I do request that this copyright
notice remain attached to the file.  You may modify this module as you
wish, but if you redistribute a modified version, please attach a note
listing the modifications you have made.

This is released under the same terms as Perl itself.

Address bug reports and comments to:
perlguy@perlguy.com

The author makes no warranties, promises, or gaurentees of this software. As with all
software, use at your own risk.

=head1 SEE ALSO

L<Apache::Htgroup>

=cut
