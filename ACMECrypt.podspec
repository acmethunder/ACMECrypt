Pod::Spec.new do |s|
  s.name             = "ACMECrypt"
  s.version          = "0.0.2"
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
	:tag => s.version
  }

  s.requires_arc = true
  
  s.subspec 'ACMECryptHelp' do |ss|
  	ss.source_files = "ACMECrypt/src/ACMEHelpMe.{h,m}"
  	ss.requires_arc = true
  end
  
  s.subspec 'ACMEHashCore' do |ss|
  	ss.source_files = "ACMECrypt/src/ACMEHash.{h,c}"
  end
  
  s.subspec 'ACMEHash' do |ss|
  	ss.source_files = "ACMECrypt/src/ACMEHashAdditions.{h,m}"
  	ss.requires_arc = true
  	ss.dependency "ACMECrypt/ACMEHashCore"
  	ss.dependency "ACMECrypt/ACMECryptHelp"
  end
  
  s.subspec 'ACMEHMACCore' do |ss|
  	ss.source_files = "ACMECrypt/src/ACMEHmac.{h,c}"
  end
  
  s.subspec 'ACMEHMAC' do |ss|
  	ss.source_files = "ACMECrypt/src/ACMEHmacAdditions.{h,m}"
  	ss.requires_arc = true
  	ss.dependency "ACMECrypt/ACMEHMACCore"
  	ss.dependency "ACMECrypt/ACMECryptHelp"
  end
  
  
  #s.dependency 'ACMEHash'

end

