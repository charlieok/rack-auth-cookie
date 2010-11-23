require 'rake'
require 'rake/clean'
require 'rake/testtask'
require 'rbconfig'

CLEAN.include("**/*.gem", "**/*.rbc")
 
namespace :gem do
  desc 'Create the rack-auth-cookie the gem'
  task :create do
    spec = eval(IO.read('rack-auth-cookie.gemspec'))
    Gem::Builder.new(spec).build
  end
   
  desc 'Install the rack-auth-cookie gem'
  task :install => [:create] do
    file = Dir["*.gem"].first
    sh "gem install #{file}"
  end
end
 
desc 'Export the git archive to a .zip, .gz and .bz2 file in your home directory'
task :export, :output_file do |t, args|
  file = args[:output_file]
 
  sh "git archive --prefix #{file}/ --output #{ENV['HOME']}/#{file}.tar master"
 
  Dir.chdir(ENV['HOME']) do
    sh "gzip -f #{ENV['HOME']}/#{file}.tar"
  end
 
  sh "git archive --prefix #{file}/ --output #{ENV['HOME']}/#{file}.tar master"
 
  Dir.chdir(ENV['HOME']) do
    sh "bzip2 -f #{ENV['HOME']}/#{file}.tar"
  end
  
  sh "git archive --prefix #{file}/ --output #{ENV['HOME']}/#{file}.zip --format zip master"
 
  Dir.chdir(ENV['HOME']) do
    sh "unzip #{file}.zip"
    Dir.chdir(file) do
      sh "rake gem"
    end
  end
end
 
Rake::TestTask.new do |t|
  t.verbose = true
  t.warning = true
end

task :default => :test
