Name:           radare2
Version:        0.9.8rc3
Release:        0%{?dist}
Summary:        %{name} reverse engineering framework
Group:          Applications/Engineering
License:        GPLv3+ 
URL:            http://www.radare.org
Source0:        https://github.com/radare/%{name}/archive/%{name}-%{version}.tar.gz
BuildRequires:  file-devel
Requires:	%{name}-devel

%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}-%{version}}

%description
The %{name} is a reverse-engineering framework that is multi-architecture,
multi-platform, and highly scriptable.  %{name} provides a hexadecimal
editor, wrapped I/O, file system support, debugger support, diffing
between two functions or binaries, and code analysis at opcode,
basic block, and function levels.

%package	devel
Summary:        Development files for the %{name} package

%description	devel
Development files for the %{name} package. See %{name} package for more
 information.

%prep
%setup -q -n %{name}-%{version}

# oops :)
sed -i "s/PKGNAME='radare2' ; VERSION='.*' ;/PKGNAME='radare2' ; VERSION='%{version}' ;/" `dirname %{SOURCE0}`/%{name}-%{version}/configure

# Use system libmagic rather than bundled
%build
%configure --with-sysmagic --with-syscapstone

#The make fails if _smp_mflags passed on command line
CFLAGS="%{optflags} -fPIC -I. -Iinclude -I../include" make

# Do not run the testsuite yet
# %check
# make tests

%install
make install DESTDIR="%{buildroot}"
chmod 0755 %{buildroot}/%{_libdir}/%{name}/%{version}/*

%files
%doc %{_datadir}/doc/%{name}
%doc COPYING
%{_bindir}/r*
%{_mandir}/man1/r*.1.*

%files	devel
%{_includedir}/libr/
%{_libdir}/pkgconfig/*.pc
%{_libdir}/%{name}/%{version}/
%{_libdir}/libr*
%{_exec_prefix}/lib/%{name}/%{version}/magic/
%{_libdir}/%{name}/last
%{_datarootdir}/%{name}/%{version}/

%post -n %{name}-devel -p /sbin/ldconfig
%postun -n %{name}-devel -p /sbin/ldconfig

%changelog
* Sun Nov 09 2014 Pavel Odvody <podvody@redhat.com> 0.9.8rc3-0
- Initial tito package
