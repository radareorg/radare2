Name:           radare2
Version:        0.9.8rc3
Release:        1%{?dist}
Summary:        radare2 reverse engineering framework
Group:          Applications/Engineering
License:        GPLv3+ 
URL:            http://www.radare.org/
Source0:        https://github.com/radare/radare2/archive/%{name}-%{version}.tar.gz
BuildRequires:  file-devel

%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}-%{version}}

%description
Radare2 is a reverse-engineering framework that is multi-architecture,
multi-platform, and highly scriptable.  Radare2 provides a hexadecmial
editor, wrapped I/O, filesystem support, debugger support, diffing
between two functions or binaries, and code analysis at opcode,
basic block, and function levels.

%package	devel
Summary:        Development files for the radare2 package

%description	devel
Development files for the radare2 package. See radare2 package for more information

%prep
%setup -q -n radare2-%{version}

# Use system libmagic rather than bundled
%build
%configure --with-sysmagic

#The make fails if _smp_mflags passed on command line
CFLAGS="%{optflags} -fPIC -I. -Iinclude -I../include" make

# Do not run the testsuite yet
# %check
# make tests

%install
make install DESTDIR="%{buildroot}"

%files
%doc %{_datadir}/doc/%{name}
%doc COPYING
%{_bindir}/r*2
%{_mandir}/man1/r*.1.*
%{_libdir}/%{name}/%{version}/
%{_libdir}/libr*

%files	devel
%{_includedir}/libr/
%{_libdir}/pkgconfig/*.pc

%changelog
* Fri Jun 27 2014 pancake <pancake@nopcode.org> 0.12.8rc3-1
- 

* Fri Jun 27 2014 pancake <pancake@nopcode.org> 0.11.8rc3-1
- new package built with tito

