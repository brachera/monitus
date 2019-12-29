# monitus
Linux Auditing aligned to ATT&amp;CK Framework

![](https://github.com/brachera/monitus/blob/master/Puppet_coverage.svg)

1. [Usage](#usage)

## Usage
These profiles are for the deployment of AuditD rules aligned to the ATT&CK Framework

To use a profile, the following line can be added to your site manifest you can simply do the following:

```ruby
include '::profiles::execution::t1064'
```

If your nodes are configured to include classes defined in Hiera, you can also do the following:

```ruby
classes:
  - profiles::execution::t1064
```

All profiles are disabled by default but can be enabled with hiera, an example for the above profile is:

```yaml
profiles::execution::t1064::enabled: true
```

This will enable the profile and for each version of python installed, an auditd rule will be created to watch for execution

