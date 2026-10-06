defmodule AnyOAuth.Error do
  defexception status: 0, code: "invalid_argument", message: "Invalid input"
end

defmodule AnyOAuth do
  @moduledoc "Generated confidential backend SDK; JSON model keys are strings."
  @json ~S|{"schemas":{"Provider":{"type":"string","enum":["google","github"]},"RedirectUri":{"type":"string","format":"uri","maxLength":2048,"x-validation":"redirect","description":"Exact registered HTTPS URL or HTTP loopback; no credentials, query or fragment."},"TokenRequest":{"type":"object","additionalProperties":false,"required":["grant_type","client_id","client_secret","code","redirect_uri","code_verifier"],"properties":{"grant_type":{"type":"string","const":"authorization_code"},"client_id":{"type":"string","maxLength":100},"client_secret":{"type":"string","minLength":1,"maxLength":200},"code":{"type":"string","minLength":1,"maxLength":200},"redirect_uri":{"$ref":"#/components/schemas/RedirectUri"},"code_verifier":{"type":"string","pattern":"^[A-Za-z0-9._~-]{43,128}$"}}},"TokenResponse":{"type":"object","required":["access_token","token_type","expires_in","scope"],"properties":{"access_token":{"type":"string","pattern":"^aop_[A-Za-z0-9_-]{43}$"},"token_type":{"type":"string","const":"Bearer"},"expires_in":{"type":"integer","const":900},"scope":{"type":"string","const":"profile"}}},"Profile":{"type":"object","required":["subject","provider","providerSubject","name","username","email","emailVerified","avatarUrl"],"properties":{"subject":{"type":"string"},"provider":{"$ref":"#/components/schemas/Provider"},"providerSubject":{"type":"string"},"name":{"type":["string","null"]},"username":{"type":["string","null"]},"email":{"type":["string","null"]},"emailVerified":{"type":"boolean"},"avatarUrl":{"type":["string","null"]}}},"ProviderStatus":{"type":"object","required":["id","configured","enabled","available"],"properties":{"id":{"$ref":"#/components/schemas/Provider"},"configured":{"type":"boolean"},"enabled":{"type":"boolean"},"available":{"type":"boolean"}}},"ProviderStatuses":{"type":"array","items":{"$ref":"#/components/schemas/ProviderStatus"}},"ApiError":{"type":"object","required":["error"],"properties":{"error":{"type":"string"},"message":{"type":"string"}}},"Transaction":{"type":"object","required":["state","codeVerifier","codeChallenge","createdAt","expiresAt"],"properties":{"state":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"},"codeVerifier":{"type":"string","pattern":"^[A-Za-z0-9._~-]{43,128}$"},"codeChallenge":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"},"createdAt":{"type":"integer"},"expiresAt":{"type":"integer"}}}},"operations":{"exchangeCode":{"id":"exchangeCode","path":"/v1/token","method":"POST","auth":"client","requestSchema":"TokenRequest","responseSchema":"TokenResponse","successStatus":200,"inputs":{"grant_type":{"constant":"authorization_code"},"client_id":{"param":"clientId"},"client_secret":{"param":"clientSecret"},"code":{"param":"code"},"redirect_uri":{"param":"redirectUri"},"code_verifier":{"param":"codeVerifier"}}},"profile":{"id":"profile","path":"/v1/profile","method":"GET","auth":"bearer","requestSchema":null,"responseSchema":"Profile","successStatus":200,"inputs":{}},"revoke":{"id":"revoke","path":"/v1/revoke","method":"POST","auth":"bearer","requestSchema":null,"responseSchema":null,"successStatus":204,"inputs":{}},"providers":{"id":"providers","path":"/api/providers","method":"GET","auth":"none","requestSchema":null,"responseSchema":"ProviderStatuses","successStatus":200,"inputs":{}}},"authorization":{"path":"/authorize","parameters":[{"name":"client_id","in":"query","required":true,"schema":{"type":"string","minLength":1}},{"name":"provider","in":"query","required":true,"schema":{"$ref":"#/components/schemas/Provider"}},{"name":"redirect_uri","in":"query","required":true,"schema":{"$ref":"#/components/schemas/RedirectUri"}},{"name":"state","in":"query","required":true,"schema":{"type":"string","minLength":16,"maxLength":512}},{"name":"code_challenge","in":"query","required":true,"schema":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"}},{"name":"code_challenge_method","in":"query","required":true,"schema":{"type":"string","const":"S256"}},{"name":"response_type","in":"query","required":true,"schema":{"type":"string","const":"code"}}]},"transaction":{"lifetimeSeconds":600,"entropyBytes":32,"description":"Create random state and a PKCE verifier/challenge. Persist this transaction in the initiating browser or app session.","input":{"type":"object","properties":{},"additionalProperties":false}},"defaultOrigin":"https://api.anyoauth.com"}|
  def descriptors, do: Jason.decode!(@json)
  def new(client_id \\ "", client_secret \\ "", base_url \\ "https://api.anyoauth.com") do
    %{client_id: client_id, client_secret: client_secret, base_url: url(base_url, true)}
  end
  defp invalid, do: raise(AnyOAuth.Error)
  defp url(value, origin \\ false) do
    unless is_binary(value) and not Regex.match?(~r/[\s\\]/, value), do: invalid()
    u = URI.parse(value)
    unless u.host && u.host != "" && is_nil(u.userinfo) && not String.contains?(value, ["?", "#"]) && not String.contains?(value |> String.split("://", parts: 2) |> List.last() |> String.split(~r/[\/?#]/) |> hd(), "@"), do: invalid()
    unless u.scheme == "https" or (u.scheme == "http" and u.host in ["localhost", "127.0.0.1", "::1"]), do: invalid()
    unless is_nil(u.port) or (is_integer(u.port) and u.port > 0 and u.port <= 65535), do: invalid()
    if origin and u.path not in [nil, "", "/"], do: invalid()
    if origin, do: String.trim_trailing(value, "/"), else: value
  end
  def validate(value, %{"$ref" => ref}), do: validate(value, descriptors()["schemas"][List.last(String.split(ref, "/"))])
  def validate(value, schema) do
    types = List.wrap(schema["type"])
    matches = %{"null"=>is_nil(value), "string"=>is_binary(value), "integer"=>is_integer(value) or (is_float(value) and value == trunc(value)), "boolean"=>is_boolean(value), "object"=>is_map(value), "array"=>is_list(value)}
    if types != [] and not Enum.any?(types, &matches[&1]), do: invalid()
    if Map.has_key?(schema,"const") and value != schema["const"], do: invalid()
    if schema["enum"] && value not in schema["enum"], do: invalid()
    if is_binary(value) do
      if String.length(value) < Map.get(schema,"minLength",0) or String.length(value) > Map.get(schema,"maxLength",1_000_000_000), do: invalid()
      if schema["pattern"] && not Regex.match?(Regex.compile!(String.replace_suffix(schema["pattern"], "$", "\\z")), value), do: invalid()
      if schema["x-validation"] == "redirect", do: url(value)
    end
    if is_map(value) do
      unless Enum.all?(Map.get(schema,"required",[]), &Map.has_key?(value,&1)), do: invalid()
      props = Map.get(schema,"properties",%{})
      if schema["additionalProperties"] == false and Enum.any?(Map.keys(value), &(not Map.has_key?(props,&1))), do: invalid()
      Enum.each(props, fn {k,s} -> if Map.has_key?(value,k), do: validate(value[k],s) end)
    end
    if is_list(value) && schema["items"], do: Enum.each(value, &validate(&1,schema["items"]))
    value
  end
  defp request(client, action, params) do
    d = descriptors(); op = d["operations"][action]
    headers = [{~c"accept", ~c"application/json"}, {~c"user-agent", ~c"AnyOAuth-elixir/0.1.0"}]
    headers = if op["auth"] == "bearer" do
      token = params["accessToken"]
      unless is_binary(token) and Regex.match?(~r/\A[A-Za-z0-9._~+\/-]+=*\z/,token), do: invalid()
      [{~c"authorization", String.to_charlist("Bearer "<>token)}|headers]
    else
      headers
    end
    body = if op["requestSchema"] do
      values = Map.merge(params,%{"clientId"=>client.client_id,"clientSecret"=>client.client_secret})
      data = Map.new(op["inputs"],fn {k,v} -> {k, if(Map.has_key?(v,"constant"),do: v["constant"],else: values[v["param"]])} end)
      validate(data,d["schemas"][op["requestSchema"]])
      Jason.encode!(data)
    else
      nil
    end
    Application.ensure_all_started(:inets)
    Application.ensure_all_started(:ssl)
    uri = String.to_charlist(client.base_url<>op["path"])
    req = if body || op["method"] in ["POST", "PUT", "PATCH"], do: {uri,headers,~c"application/json",body || ""}, else: {uri,headers}
    # HTTP verbs are selected from generator-validated descriptors, never caller input.
    method = Map.fetch!(%{"GET"=>:get,"POST"=>:post,"PUT"=>:put,"PATCH"=>:patch,"DELETE"=>:delete,"HEAD"=>:head,"OPTIONS"=>:options},op["method"])
    options = [autoredirect: false, timeout: 10_000, connect_timeout: 10_000, ssl: [verify: :verify_peer, cacerts: :public_key.cacerts_get(), customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]]]
    case :httpc.request(method,req,options,[body_format: :binary]) do
      {:ok, {{_,status,_},_,raw}} -> decode(status,raw,op,d)
      _ -> raise AnyOAuth.Error, status: 0, code: "transport_error", message: "HTTP request failed"
    end
  end
  defp decode(status,raw,op,d) do
    if status != op["successStatus"] do
      if status >= 200 and status < 300, do: raise(AnyOAuth.Error, status: status, code: "protocol_error", message: "Unexpected response status")
      {code, message} = try do
        error = validate(Jason.decode!(raw),d["schemas"]["ApiError"])
        {error["error"], Map.get(error, "message", "HTTP request failed")}
      rescue
        _ -> {"protocol_error", "Invalid error response"}
      end
      raise AnyOAuth.Error, status: status, code: code, message: message
    end
    if op["responseSchema"] do
      try do
        validate(Jason.decode!(raw),d["schemas"][op["responseSchema"]])
      rescue
        _ -> raise AnyOAuth.Error, status: status, code: "protocol_error", message: "Invalid API response"
      end
    else
      nil
    end
  end
  def exchange_code(client, params \\ %{}), do: request(client, "exchangeCode", params)
  def profile(client, params \\ %{}), do: request(client, "profile", params)
  def revoke(client, params \\ %{}), do: request(client, "revoke", params)
  def providers(client, params \\ %{}), do: request(client, "providers", params)
  def pkce_challenge(_client, params) do
    v = params["codeVerifier"]
    unless is_binary(v) and Regex.match?(~r/\A[A-Za-z0-9._~-]{43,128}\z/,v), do: invalid()
    Base.url_encode64(:crypto.hash(:sha256,v), padding: false)
  end
  def create_transaction(client, _params \\ %{}) do
    settings = descriptors()["transaction"]
    state = Base.url_encode64(:crypto.strong_rand_bytes(settings["entropyBytes"]),padding: false)
    v = Base.url_encode64(:crypto.strong_rand_bytes(settings["entropyBytes"]),padding: false)
    now = System.system_time(:second)
    validate(%{"state"=>state,"codeVerifier"=>v,"codeChallenge"=>pkce_challenge(client,%{"codeVerifier"=>v}),"createdAt"=>now,"expiresAt"=>now+settings["lifetimeSeconds"]},descriptors()["schemas"]["Transaction"])
  end
  def authorization_url(client, params) do
    d = descriptors(); values = Map.put(params,"clientId",client.client_id)
    query = Map.new(d["authorization"]["parameters"],fn p ->
      s = p["schema"]; key = Regex.replace(~r/_([a-z])/,p["name"],fn _,c -> String.upcase(c) end)
      {p["name"],validate(if(Map.has_key?(s,"const"),do: s["const"],else: values[key]),s)}
    end)
    client.base_url<>d["authorization"]["path"]<>"?"<>URI.encode_query(query)
  end
  def validate_callback(_client, params) do
    redirect = url(params["redirectUri"])
    callback = params["callbackUrl"]; state = params["state"]; expiry = params["expiresAt"]
    unless is_binary(state) and state != "" and is_integer(expiry) and expiry > System.system_time(:second), do: invalid()
    unless is_binary(callback) and not Regex.match?(~r/[\s\\#]/,callback) and hd(String.split(callback,"?",parts: 2)) == redirect, do: invalid()
    query = Enum.at(String.split(callback,"?",parts: 2),1,"")
    if Regex.match?(~r/%(?![0-9A-Fa-f]{2})/,query), do: invalid()
    pairs = query |> URI.query_decoder() |> Enum.group_by(&elem(&1,0),&elem(&1,1))
    if Enum.any?(["state","code","error"], &(length(Map.get(pairs,&1,[])) > 1)), do: invalid()
    actual = hd(Map.get(pairs,"state",[""]))
    # Hash to a fixed size before constant-time comparison on all supported OTPs.
    unless :crypto.hash_equals(:crypto.hash(:sha256,state),:crypto.hash(:sha256,actual)), do: invalid()
    if Map.has_key?(pairs,"code") == Map.has_key?(pairs,"error"), do: invalid()
    key = if Map.has_key?(pairs,"code"),do: "code",else: "error"
    if hd(pairs[key]) == "", do: invalid()
    %{key=>hd(pairs[key]),"state"=>actual}
  end
end
