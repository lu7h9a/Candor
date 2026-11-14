# Binary RPM from the staged tree (packaging/build.sh passes _stage and
# _version). Plan WP30, D21: the service is installed, never enabled.
Name:           sysscope
Version:        %{_version}
Release:        1
Summary:        Process monitor that explains what programs do (eBPF)
License:        MIT
Group:          System Environment/Daemons
Packager:       SysScope <noreply@github.com>
URL:            https://github.com/lu7h9a/sysscope
Requires:       systemd
Recommends:     bubblewrap
AutoReqProv:    yes
%global debug_package %{nil}
%global __strip /bin/true

%description
SysScope shows what every program on the computer is doing (programs
started, files opened, network connections), flags suspicious behaviour
with plain-language explanations, and can run a program in a sandbox to
show what it touches. The daemon watches the processes of all users.

%install
cp -a %{_stage}/. %{buildroot}/

%post
systemd-sysusers /usr/lib/sysusers.d/sysscope.conf || :
systemctl daemon-reload >/dev/null 2>&1 || :
cat /usr/share/doc/sysscope/postinstall-message.txt

%preun
if [ "$1" -eq 0 ]; then
    systemctl disable --now sysscoped.service >/dev/null 2>&1 || :
fi

%postun
if [ "$1" -eq 0 ]; then
    rm -rf /run/sysscope /var/lib/sysscope
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%files
/usr/bin/sysscoped
/usr/bin/sysscope
/usr/bin/sysscope-gui
/usr/bin/sysscope-glasshouse
/usr/lib/systemd/system/sysscoped.service
/usr/lib/sysusers.d/sysscope.conf
%dir /etc/sysscope
%config(noreplace) /etc/sysscope/rules.toml
%config(noreplace) /etc/sysscope/allow.toml
%config(noreplace) /etc/sysscope/sysscoped.toml
/usr/share/applications/sysscope.desktop
%dir /usr/share/icons/hicolor
%dir /usr/share/icons/hicolor/scalable
%dir /usr/share/icons/hicolor/scalable/apps
/usr/share/icons/hicolor/scalable/apps/sysscope.svg
%dir /usr/share/doc/sysscope
/usr/share/man/man1/sysscope.1.gz
/usr/share/man/man1/sysscope-gui.1.gz
/usr/share/man/man8/sysscoped.8.gz
/usr/share/man/man8/sysscope-glasshouse.8.gz
%license /usr/share/doc/sysscope/LICENSE
%doc /usr/share/doc/sysscope/README.md
%doc /usr/share/doc/sysscope/THREAT_MODEL.md
%doc /usr/share/doc/sysscope/REAL_SAMPLES.md
%doc /usr/share/doc/sysscope/postinstall-message.txt

%changelog
* Sat Nov 14 2026 SysScope <noreply@github.com> - %{_version}-1
- Release %{_version}.
