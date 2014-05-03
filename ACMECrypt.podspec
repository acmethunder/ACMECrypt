Pod::Spec.new do |s|
  s.name             = "ACMECrypt"
  s.version          = "0.0.1"
  s.summary          = "Some convenince methods for hashing data."
  s.homepage         = "https://github.com/mdewolfe/ACMECrypt"
  s.license          = "MIT"
  s.license          = { :type => "MIT", :file => "LICENSE" }
  s.author           = { "Mike De Wolfe" => "dewolfe.michael@gmail.com" }
  s.social_media_url = "http://twitter.com/mikedewolfe"

  #  When using multiple platforms
  s.ios.deployment_target = "5.0"
  s.osx.deployment_target = "10.7"

  s.source = {
	:git => "https://github.com/mdewolfe/ACMECrypt.git",
	:commit => "5280ae5a823dac1b7fe202da325492d8b0a3597c"
  }

  s.requires_arc = true
  s.frameworks = "Security"
  
  s.subspec 'ACMEHashCore' do |ss|
  	ss.source_files = "ACMECrypt/src/ACMEHash.{h,c}"
  end
  
  s.subspec 'ACMEHash' do |ss|
  	ss.source_files = 'ACMECrypt/src/ACMEHelpers.{h,m}'
  	ss.requires_arc = true
  	ss.dependency 'ACMECrypt/ACMEHashCore'
  end
  
  
  #s.dependency 'ACMEHash'

end

