package LUCCDC::Stig::SSH;

use base qw(Exporter);

our @EXPORT      = qw();
our @EXPORT_OK   = qw(check_sshd_config);
our %EXPORT_TAGS = (
    ALL => [ @EXPORT, @EXPORT_OK ],
);


sub check_sshd_config {
    my ($config_file) = @_;

    open my $file, '<', $config_file
        or die "Can't open $config_file";

    my %config = ();
    while (my $line = <$file>)  {
        chomp $line; # Cut off newline
        my ($key, $value) = split(/\s/, $line, 2);
        $config{$key} = $value;
    }

    if($config{"PermitRootLogin"} eq "yes") {
        print "Warning: Root SSH Login Allowed";
    } else {
        print "Safe!"
    }

}

1;
