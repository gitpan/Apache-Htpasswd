# -*- perl -*-
# $Id: Makefile.PL,v 1.1.1.1 2002/07/26 18:58:46 root Exp $
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Apache::Htpasswd',
   VERSION_FROM  => 'Htpasswd.pm',
   'dist'        => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
   'clean'       => { FILES => q[*% *.bak *.old *.test]},
);

