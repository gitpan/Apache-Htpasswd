# $Id: test.pl,v 0.3 1998/10/22 02:49:53 meltzek Exp $
# $Log: test.pl,v $
# Revision 0.3  1998/10/22 02:49:53  meltzek
# Added verbose begining and ending of test.
#
# Revision 0.2  1998/10/22 02:46:56  meltzek
# Added new checks.
#

BEGIN { $| = 1; print "Tests 1..10 begining\n"; }
END {print "not ok 1\n" unless $loaded;}
use Apache::Htpasswd;

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

sub report_result {
	my $ok = shift;
	$TEST_NUM ||= 2;
	print "not " unless $ok;
	print "ok $TEST_NUM\n";
	print "@_\n" if (not $ok and $ENV{TEST_VERBOSE});
	$TEST_NUM++;
}

# Create a test password file
my $File = "testpasswords.test";
open(TEST,">$File");
print TEST "kevin:kjDqW.pgNIz3Ufoo:suvPq./X7Q8nk\n";
close TEST;



{
	
	# 2: Get file
	&report_result($pwdFile = new Apache::Htpasswd ($File), $! );

	# 3: store a value
	&report_result($pwdFile->htpasswd("foo","foobar") , $! );

	# 4: change value 
	&report_result($pwdFile->htpasswd("foo", "goo","foobar" ) , $! );
	
	# 5: force change value
	&report_result($pwdFile->htpasswd("foo","ummm",1), $! );

	# 6: check the stored value
	&report_result($pwdFile->fetchPass("foo") , $!);

	# 7: check whether the empty key exists()
	&report_result($pwdFile->htCheckPassword("foo","ummm"),$!);

	# 8: add extra info
	&report_result($pwdFile->writeInfo("kevin", "Test info"),$!);
	
	# 9: fetch extra info
	&report_result($pwdFile->fetchInfo("kevin"),$!);
	
	# 10: Delete user
	&report_result($pwdFile->htDelete("kevin"),$!);
	
        # 11: get list
        my @list = $pwdFile->fetchUsers();
        &report_result($list[0] eq 'foo', $!);

	# 12: get number of users
        my $num  = $pwdFile->fetchUsers();
        &report_result($num == 1, $!);

	undef $pwdFile;

	# 13: Create in read-only mode
        &report_result($pwdFile = new Apache::Htpasswd({passwdFile => $File, ReadOnly => 1}), $! );

        # 14: store a value (should fail)
	# Should carp, but don't want to display it
	sub Apache::Htpasswd::carp {};
        &report_result(!$pwdFile->htpasswd("kevin","zog") , $! );
	
}

print "Test complete.\n";
