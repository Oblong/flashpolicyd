require 'flashpolicyd'


policy = PolicyServer.new({
  'port' => 2000,
  'xml' => <<-eos
<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <site-control permitted-cross-domain-policies="master-only"/>
  <allow-access-from domain="*" to-ports="*" />
</cross-domain-policy>'
  eos
})

loop {
  sleep 10
}
