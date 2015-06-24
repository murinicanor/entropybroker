Name:		entropy-broker
Version: 2.4
Release:	1%{?dist}
Summary:	entropy broker

Group: System Environment/Daemons
License: GPL	
URL:	http://www.vanheusden.com/entropybroker/	
Source0: entropy-broker-2.4.tar.gz	
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: cryptopp-devel, gd-devel, zlib-devel, libpng-devel
Requires:	cryptopp, gd, zlib, libpng

%description
entropy broker daemon

%package server
Summary: entropy broker server
%description server
entropy broker server

%package client
Summary: entropy broker client binaries
Requires: cryptopp
%description client
entropy broker client

%prep
%setup -q


%build
%configure
make %{?_smp_mflags} everything PREFIX=/usr ETC=/etc/entropybroker VAR=/var/ CACHE=/var/cache/entropybroker


%install
rm -rf %{buildroot}
make install PREFIX=%{buildroot}/usr ETC=%{buildroot}/etc/entropybroker VAR=%{buildroot}/var CACHE=%{buildroot}/var/cache/entropybroker
mv %{buildroot}/usr/share/man/man8 %{buildroot}/usr/share/man/man1
install -D -m 755 -d %{buildroot}/etc/init.d/
install -m 755 redhat/* %{buildroot}/etc/init.d/

%clean
rm -rf %{buildroot}


%files server
%defattr(-,root,root,-)
%doc /usr/doc/entropy_broker/readme.txt
%doc /usr/doc/entropy_broker/network_protocol.txt
%doc /usr/doc/entropy_broker/interfacing.txt
%doc /usr/doc/entropy_broker/users.txt
%doc /usr/doc/entropy_broker/license.txt
%doc /usr/doc/entropy_broker/auth.txt
%doc /usr/doc/entropy_broker/design.txt
%config(noreplace) /etc/entropybroker/entropy_broker.conf
%config /etc/entropybroker/entropy_broker.conf.dist
%config(noreplace) /etc/entropybroker/users.txt
/usr/bin/eb_server_Araneus_Alea
/usr/bin/eb_server_ext_proc
/usr/bin/eb_server_timers
/usr/bin/eb_server_usb
/usr/bin/eb_server_linux_kernel
/usr/bin/entropy_broker
/usr/bin/eb_server_v4l
/usr/bin/eb_server_cycle_count
/usr/bin/eb_proxy_knuth_b
/usr/bin/eb_server_stream
/usr/bin/eb_server_push_file
/usr/bin/eb_proxy_knuth_m
/usr/bin/eb_server_ComScire_R2000KU
/usr/bin/eb_server_egd
/usr/share/eb/web/404.html
/usr/share/eb/web/stylesheet.css
/usr/share/eb/web/statistics.png
/usr/share/eb/web/favicon.ico
/usr/share/eb/web/logo.png
/usr/share/eb/web/logfiles.png
/usr/share/eb/web/logo-bw.png
/usr/share/eb/web/users.png
/usr/share/man/man1/eb_server_audio.1.gz
/usr/share/man/man1/eb_server_egd.1.gz
/usr/share/man/man1/eb_server_ext_proc.1.gz
/usr/share/man/man1/eb_server_linux_kernel.1.gz
/usr/share/man/man1/eb_server_push_file.1.gz
/usr/share/man/man1/eb_server_stream.1.gz
/usr/share/man/man1/eb_server_timers.1.gz
/usr/share/man/man1/eb_server_v4l.1.gz
/usr/share/man/man1/entropy_broker.1.gz
/usr/share/man/man1/test_egd_speed.1.gz
/etc/init.d/eb_server_audio
/etc/init.d/eb_server_ComScire_R2000KU
/etc/init.d/eb_server_cycle_count
/etc/init.d/eb_server_egd
/etc/init.d/eb_server_ext_proc
/etc/init.d/eb_server_linux_kernel
/etc/init.d/eb_server_push_file
/etc/init.d/eb_server_smartcard
/etc/init.d/eb_server_stream
/etc/init.d/eb_server_timers
/etc/init.d/eb_server_usb
/etc/init.d/eb_server_v4l
/etc/init.d/entropy_broker

%files client
%doc /usr/doc/entropy_broker/readme.txt
%doc /usr/doc/entropy_broker/network_protocol.txt
%doc /usr/doc/entropy_broker/interfacing.txt
%doc /usr/doc/entropy_broker/users.txt
%doc /usr/doc/entropy_broker/license.txt
%doc /usr/doc/entropy_broker/auth.txt
%doc /usr/doc/entropy_broker/design.txt
/usr/bin/eb_client_egd
/usr/bin/eb_client_kernel_generic
/usr/bin/eb_client_file
/usr/bin/eb_client_linux_kernel
/etc/init.d/eb_client_egd
/etc/init.d/eb_client_file
/etc/init.d/eb_client_linux_kernel
/usr/share/man/man1/eb_client_egd.1.gz
/usr/share/man/man1/eb_client_file.1.gz
/usr/share/man/man1/eb_client_linux_kernel.1.gz


%changelog

