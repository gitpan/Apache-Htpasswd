# -*- perl -*-
# $Id: Makefile.PL,v 0.01 1998/28/9 09:45:13 kmeltz Exp $
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Apache::Htpasswd',
   VERSION_FROM  => 'Htpasswd.pm',
   'dist'        => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
   'clean'       => { FILES => " *.old"},
);

