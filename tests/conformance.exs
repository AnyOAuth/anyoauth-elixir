out = try do
  v = Jason.decode!(IO.read(:stdio,:eof))
  client = AnyOAuth.new(Map.get(v,"clientId",""),Map.get(v,"clientSecret",""),Map.get(v,"baseUrl","https://api.anyoauth.com"))
  methods = %{"exchangeCode"=>:exchange_code,"profile"=>:profile,"revoke"=>:revoke,"providers"=>:providers,"pkceChallenge"=>:pkce_challenge,"authorizationUrl"=>:authorization_url,"validateCallback"=>:validate_callback,"createTransaction"=>:create_transaction}
  method = Map.get(methods,v["action"])
  if is_nil(method), do: raise(AnyOAuth.Error)
  %{"ok"=>true,"result"=>apply(AnyOAuth,method,[client,Map.get(v,"params",%{})])}
rescue
  e in AnyOAuth.Error -> %{"ok"=>false,"error"=>%{"status"=>e.status,"code"=>e.code,"message"=>e.message}}
  _ -> %{"ok"=>false,"error"=>%{"status"=>0,"code"=>"invalid_argument","message"=>"Invalid input"}}
end
IO.puts(Jason.encode!(out))
