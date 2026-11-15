# Binary RPM from the staged tree (packaging/build.sh passes _stage and
# _version). Plan WP30, D21: the service is installed, never enabled.
Name:           candor
Version:        %{_version}
Release:        1
Summary:        Process monitor that explains what programs do (eBPF)
License:        MIT
Group:          System Environment/Daemons
Packager:       Candor <noreply@github.com>
URL:            https://github.com/lu7h9a/candor
Requires:       systemd
Recommends:     bubblewrap
AutoReqProv:    yes
%global debug_package %{nil}
%global __strip /bin/true

%description
Candor shows what every program on the computer is doing (programs
started, files opened, network connections), flags suspicious behaviour
with plain-language explanations, and can run a program in a sandbox to
show what it touches. The daemon watches the processes of all users.

%install
cp -a %{_stage}/. %{buildroot}/

%post
systemd-sysusers /usr/lib/sysusers.d/candor.conf || :
systemctl daemon-reload >/dev/null 2>&1 || :
cat /usr/share/doc/candor/postinstall-message.txt

%preun
if [ "$1" -eq 0 ]; then
    systemctl disable --now candord.service >/dev/null 2>&1 || :
fi

%postun
if [ "$1" -eq 0 ]; then
    rm -rf /run/candor /var/lib/candor
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%files
/usr/bin/candord
/usr/bin/candor
/usr/bin/candor-gui
/usr/bin/candor-glasshouse
/usr/lib/systemd/system/candord.service
/usr/lib/sysusers.d/candor.conf
%dir /etc/candor
%config(noreplace) /etc/candor/rules.toml
%config(noreplace) /etc/candor/allow.toml
%config(noreplace) /etc/candor/candord.toml
/usr/share/applications/candor.desktop
%dir /usr/share/icons/hicolor
%dir /usr/share/icons/hicolor/scalable
%dir /usr/share/icons/hicolor/scalable/apps
/usr/share/icons/hicolor/scalable/apps/candor.svg
%dir /usr/share/doc/candor
/usr/share/man/man1/candor.1.gz
/usr/share/man/man1/candor-gui.1.gz
/usr/share/man/man8/candord.8.gz
/usr/share/man/man8/candor-glasshouse.8.gz
%license /usr/share/doc/candor/LICENSE
%dir /usr/share/doc/candor/fonts
%license /usr/share/doc/candor/fonts/OFL-Inter.txt
%license /usr/share/doc/candor/fonts/OFL-JetBrainsMono.txt
%doc /usr/share/doc/candor/README.md
%doc /usr/share/doc/candor/THREAT_MODEL.md
%doc /usr/share/doc/candor/REAL_SAMPLES.md
%doc /usr/share/doc/candor/postinstall-message.txt

%changelog
* Sat Nov 14 2026 Candor <noreply@github.com> - %{_version}-1
- Release %{_version}.
