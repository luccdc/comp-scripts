package LUCCDC::Util::systemd;

use base qw(Exporter);

our @EXPORT      = qw();
our @EXPORT_OK   = qw(is_active is_enabled is_loaded);
our %EXPORT_TAGS = (
    ALL => [ @EXPORT, @EXPORT_OK ],
);

sub is_active {
    my ($unit) = @_;
    system('systemctl', '-q', 'is-active', $unit) == 0;
}

sub is_enabled {
    my ($unit) = @_;
    system('systemctl', '-q', 'is-enabled', $unit) == 0;
}

sub is_loaded {
    my ($unit) = @_;
    my $loadstate = `systemctl show -p LoadState --value "$unit" 2>/dev/null`;
    chomp $loadstate;
    return $loadstate eq 'loaded';
}

1;
