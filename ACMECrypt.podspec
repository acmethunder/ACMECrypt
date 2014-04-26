Pod::Spec.new do |s|
  s.name         = "ACMECrypt"
  s.version      = "0.0.1"
  s.summary      = "Some convenince methods for hashing, signing, and ecryption."
  s.homepage     = "https://github.com/mdewolfe/ACMECrypt"
  s.license      = "MIT"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "Mike De Wolfe" => "dewolfe.michael@gmail.com" }
  s.social_media_url   = "http://twitter.com/mikedewolfe"

  #  When using multiple platforms
  s.ios.deployment_target = "5.0"
  s.osx.deployment_target = "10.7"

  s.source = {
	:git => "https://github.com/mdewolfe/ACMECrypt.git",
	:commit => "a3eff810b7a07de581dd18fd96b75614a3ee76c1"
  }

  s.source_files  = "ACMECrypt/src"



  s.requires_arc = true
  s.frameworks = "Security"

end

