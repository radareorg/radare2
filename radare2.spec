Name:           radare2
Version:        0.9.8rc3
Release:        1%{?dist}
Summary:        radare2 reverse engineering framework
Group:          Applications/Engineering
License:        GPLv3+ 
URL:            http://www.radare.org/
Source0:        https://github.com/radare/radare2/archive/%{version}.tar.gz
BuildRequires:  file-devel

%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}-%{version}}

%description
Radare2 is a reverse-engineering framework that is multi-architecture,
multi-platform, and highly scriptable.  Radare2 provides a hexadecmial
editor, wrapped I/O, filesystem support, debugger support, diffing
between two functions or binaries, and code analysis at opcode,
basic block, and function levels.

%prep
%setup -q -n radare2-%{version}

# Use system libmagic rather than bundled
%build
%configure --with-sysmagic

#The make fails if _smp_mflags passed on command line
make CFLAGS="%{optflags} -fPIC -I../include"

%check
make tests

%install
make install DESTDIR="%{buildroot}"

%files
%doc COPYING
%{_bindir}/%{name}

%changelog
