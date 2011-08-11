require 'flashpolicyd'


policy = PolicyServer.new({
  'port' => 2000
})

loop {
  sleep 10
}
