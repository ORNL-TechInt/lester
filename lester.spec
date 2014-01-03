Name:           lester
Version:        1.0
Release:        1%{?dist}
Summary:        Lester, the Lustre lister

#Group:          
License:        GPLv2
URL:            https://github.com/ORNL-TechInt/lester
Source0:        https://github.com/ORNL-TechInt/lester-1.0.tar.gz
Packager:       Blake Caldwell <blakec@ornl.gov>

BuildRequires:  e2fsprogs-devel >= 1.42.7
BuildRequires:  libcom_err-devel >= 1.42.7
BuildRequires:  libaio-devel
BuildRequires:  autoconf
BuildRequires:  automake
Requires:       e2fsprogs-libs >= 1.42.7
Requires:       libcom_err >= 1.42.7
Requires:       libaio

%description
Lester is an extention of e2scan for generating lists of files (and potentially
their attributes) from a ext2/ext3/ext4/ldiskfs filesystem.

%prep
%setup -q


%build
./bootstrap
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc README
/usr/bin/lester



%changelog
* Tue Dec 31 2013 Blake Caldwell <blakec@ornl.gov> - 1.0
- Initial RPM packaging of lester
