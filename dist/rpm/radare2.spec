%global         gituser         radareorg
%global         gitname         radare2
#global         commit          5a3dab0a86e1452c0bb0c13d869f95b41f50b9a9
%global         commit          5860c3efc12d4b75e72bdce4b1d3834599620913
%global         shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:           radare2
Version:        5.1.0
Release:        1%{?dist}
Summary:        The %{name} reverse engineering framework
Group:          Applications/Engineering
License:        LGPLv3
URL:            https://www.radare.org/
#Source0:        http://radare.org/get/%{name}-%{version}.tar.gz
#Source0:        http://radare.org/get/%{name}-%{version}.tar.xz
# Source0:        https://github.com/%{gituser}/%{gitname}/archive/%{commit}/%{name}-%{version}-%{shortcommit}.tar.gz
Source0:        https://github.com/%{gituser}/%{gitname}/archive/%{commit}/%{name}-%{version}-git.tar.gz


BuildRequires:  file-devel
BuildRequires:  libzip-devel
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
%setup -q -n %{gitname}-%{commit}


%build
%configure --with-sysmagic --with-syszip #--with-syscapstone
CFLAGS="%{optflags} -fPIC -I../include" make %{?_smp_mflags} LIBDIR=%{_libdir} PREFIX=%{_prefix} DATADIR=%{DATADIR}

# Do not run the testsuite yet
# %check
# make tests


%install
rm -rf %{buildroot}
NOSUDO=1 make install DESTDIR=%{buildroot} LIBDIR=%{_libdir} PREFIX=%{_prefix}
cp shlr/sdb/src/libsdb.a %{buildroot}/%{_libdir}/libsdb.a

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig


%files
%doc AUTHORS.md CONTRIBUTING.md DEVELOPERS.md README.md TODO.md
%license COPYING
%{_bindir}/r*
%{_libdir}/libr*
%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/%{version}-git
%{_libdir}/%{name}/last
%{_libdir}/%{name}/%{version}-git/*.so
#%{_libdir}/%{name}/%{version}-git/*.py*
#%{_libdir}/%{name}/%{version}-git/*.lua
#%{_libdir}/%{name}/%{version}-git/*.rb
%{_libdir}/%{name}/%{version}-git/hud
%{_libdir}/%{name}/%{version}-git/syscall
%{_libdir}/%{name}/%{version}-git/opcodes
%dir %{_prefix}/lib/%{name}
%dir %{_prefix}/lib/%{name}/%{version}-git
%dir %{_prefix}/lib/%{name}/%{version}-git/magic
%{_prefix}/lib/%{name}/%{version}-git/magic/*
%{_mandir}/man1/r*.1.*
%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/%{version}-git
%dir %{_datadir}/%{name}/%{version}-git/cons
%{_datadir}/%{name}/%{version}-git/cons/*
%dir %{_datadir}/%{name}/%{version}-git/format
%{_datadir}/%{name}/%{version}-git/format/*
%dir %{_prefix}/%{name}/%{version}-git/r2pm
%{_prefix}/%{name}/%{version}-git/r2pm/*
%dir %{_datadir}/%{name}/%{version}-git/www
%{_datadir}/%{name}/%{version}-git/www/*


%files devel
%{_includedir}/libr
%{_libdir}/libsdb.a
%{_libdir}/pkgconfig/*.pc

%post -n %{name}-devel -p /sbin/ldconfig
%postun -n %{name}-devel -p /sbin/ldconfig


%changelog
* Sat Oct 10 2020 pancake <pancake@nopcode.org> 5.1.0
- update for latest centos8 and r2 codebase

* Sat Oct 10 2015 Michal Ambroz <rebus at, seznam.cz> 0.10.0-1
- build for Fedora for alpha of 0.10.0

* Sun Nov 09 2014 Pavel Odvody <podvody@redhat.com> 0.9.8rc3-0
- Initial tito package

