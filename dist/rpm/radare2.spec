%global         gituser         radareorg
%global         gitname         radare2
%global         commit          151a020573abca7b926f71a801484dee830627d1
%global         shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:           radare2
Version:        6.0.8
Release:        1%{?dist}
Summary:        The %{name} reverse engineering framework
Group:          Applications/Engineering
License:        LGPLv3
URL:            https://www.radare.org/
Source0:        https://github.com/%{gituser}/%{gitname}/archive/refs/tags/%{version}.tar.gz


# BuildRequires:  file-devel
# BuildRequires:  libzip-devel
#BuildRequires:  capstone-devel >= 3.0.4

#Assume more versions installed in paraller side-by-side
%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}-%{version}}

%description
The %{name} is a reverse-engineering framework that is multi-architecture,
multi-platform, and highly scriptable.  %{name} provides a hexadecimal
editor, wrapped I/O, file system support, debugger support, diffing
between two functions or binaries, and code analysis at opcode,
basic block, and function levels.


%package devel
Summary:        Development files for the %{name} package
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description devel
Development files for the %{name} package. See %{name} package for more
information.


%prep
#%setup -q -n %{name}-%{version}
%setup -q -n %{gitname}-%{version}


%build
%configure --with-sysmagic --with-syszip #--with-syscapstone
CFLAGS="%{optflags} -fPIC -I../include" make %{?_smp_mflags} LIBDIR=%{_libdir} PREFIX=%{_prefix} DATADIR=%{DATADIR}

# Do not run the testsuite yet
# %check
# make tests


%install
rm -rf %{buildroot}
NOSUDO=1 make install DESTDIR=%{buildroot} LIBDIR=%{_libdir} PREFIX=%{_prefix}
# cp shlr/sdb/src/libsdb.a %{buildroot}/%{_libdir}/libsdb.a
# 5.9.9 : cp subprojects/sdb/src/libsdb.a %{buildroot}/%{_libdir}/libsdb.a

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig


%files
%doc COMMUNITY.md CONTRIBUTING.md DEVELOPERS.md INSTALL.md README.md SECURITY.md USAGE.md
%license COPYING.md
%{_bindir}/r*
%{_bindir}/clang-format-radare2
%{_libdir}/libr*
%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/%{version}
%{_libdir}/%{name}/last
%{_libdir}/%{name}/%{version}/*.so
%{_datadir}/%{name}/last
%{_datadir}/%{name}/%{version}/hud
%{_datadir}/%{name}/%{version}/cons
%{_datadir}/%{name}/%{version}/syscall
%{_datadir}/%{name}/%{version}/opcodes
%{_datadir}/%{name}/%{version}/format
%{_datadir}/%{name}/%{version}/fcnsign
%{_datadir}/%{name}/%{version}/flag
%{_datadir}/%{name}/%{version}/platform
%{_datadir}/%{name}/%{version}/scripts
%{_datadir}/doc/%{name}
%dir %{_prefix}/share/%{name}
%dir %{_prefix}/share/%{name}/%{version}
%dir %{_prefix}/share/%{name}/%{version}/magic
%{_prefix}/share/%{name}/%{version}/magic/*
%{_mandir}/man1/r*.1.*
%{_mandir}/man3/r_*.3.*
%{_mandir}/man7/esil.7.*
%dir %{_datadir}/%{name}/%{version}/www
%{_datadir}/%{name}/%{version}/www/*
%{_datadir}/%{name}/%{version}/panels/*
%dir %{_datadir}/%{name}/%{version}/fortunes
%{_datadir}/%{name}/%{version}/fortunes/*

%files devel
%{_includedir}/libr
%{_libdir}/pkgconfig/*.pc

%post -n %{name}-devel -p /sbin/ldconfig
%postun -n %{name}-devel -p /sbin/ldconfig


%changelog
* Tue Jan 10 2023 pancake <pancake@nopcode.org> 6.0.7
- lots of bug fixes and memory leaks

* Tue Jan 10 2023 pancake <pancake@nopcode.org> 5.8.0
- remove system deps and integrate it in the build system

* Mon Sep 20 2021 pancake <pancake@nopcode.org> 5.4.2
- update for latest centos8 and r2 codebase

* Sat Oct 10 2020 pancake <pancake@nopcode.org> 5.1.0
- update for latest centos8 and r2 codebase

* Sat Oct 10 2015 Michal Ambroz <rebus at, seznam.cz> 0.10.0-1
- build for Fedora for alpha of 0.10.0

* Sun Nov 09 2014 Pavel Odvody <podvody@redhat.com> 0.9.8rc3-0
- Initial tito package

