require 'sinatra'
require 'logger'
require 'json'
require 'openssl'
require 'octokit'
require 'jwt'
require 'time' # This is necessary to get the ISO 8601 representation of a Time object
require 'git'
require 'simplabs/excellent'
require 'fileutils'

#
#
# This is a boilerplate server for your own GitHub App. You can read more about GitHub Apps here:
# https://developer.github.com/apps/
#
# On its own, this app demonstrates how to use the Checks API to create a CI server, but otherwise
# it doesn't do much. It's up to you to add fun functionality!
#
# Have fun! Please reach out to us TODO HOW if you have any questions, or just to show off what you've built!
#

class GHAapp < Sinatra::Application

# Never, ever, hardcode app tokens or other secrets in your code!
# Always extract from a runtime source, like an environment variable.


# Notice that the private key must be in PEM format, but the newlines should be stripped and replaced with
# the literal `\n`. This can be done in the terminal as such:
# export GITHUB_PRIVATE_KEY=`awk '{printf "%s\\n", $0}' private-key.pem`
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n")) # convert newlines

# You set the webhook secret when you create your app. This verifies that the webhook is really coming from GH
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

# Get the app identifier—an integer—from your app page after you create your app. This isn't actually a secret,
# but it is something easier to configure at runtime
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']


########## Configure Sinatra
#
# Let's turn on verbose logging during development
#
  configure :development do
    set :logging, Logger::DEBUG
  end


########## Before each request to our app
#
# Before each request to our app, we want to instantiate an Octokit client. Doing so requires that we construct a JWT.
# https://jwt.io/introduction/
# We have to also sign that JWT with our private key, so GitHub can be sure that
#  a) it came from us
#  b) it hasn't been altered by a malicious third party
#
  before do
    payload = {
        # The time that this JWT was issued, _i.e._ now.
        iat: Time.now.to_i,

        # How long is the JWT good for (in seconds)?
        # Let's say it can be used for 10 minutes before it needs to be refreshed.
        # TODO we don't actually cache this token, we regenerate a new one every time!
        exp: Time.now.to_i + (10 * 60),

        # Your GitHub App's identifier number, so GitHub knows who issued the JWT, and know what permissions
        # this token has.
        iss: APP_IDENTIFIER
    }

    # Cryptographically sign the JWT
    jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

    # Create the Octokit client, using the JWT as the auth token.
    # Notice that this client will _not_ have sufficient permissions to do many interesting things!
    # We might, for particular endpoints, need to generate an installation token (using the JWT), and instantiate
    # a new client object. But we'll cross that bridge when/if we get there!
    # TODO Octokit should handle that token exchange transparently for us
    @client ||= Octokit::Client.new(bearer_token: jwt)
  end


########## Events
#
# This is the webhook endpoint that GH will call with events, and hence where we will do our event handling
#

  post '/event_handler' do
    # First, a bit of security
    check_signature!

    # Determine what kind of event this is, and take action as appropriate
    # TODO we assume that GitHub will always provide an X-GITHUB-EVENT header in this case, which is a reasonable
    #      assumption, however we should probably be more careful!
    event = request.env['HTTP_X_GITHUB_EVENT'].to_sym
    action = @payload['action'].to_sym || nil
    logger.debug "---- recevied event #{event}"
    logger.debug "----         action #{action}" unless action.nil?

    case event
    when :check_suite
      # A new check_suite has been created or rerequested. Create a new check_run
      if action == :requested || action == :rerequested
        create_check_run
      end

    when :check_run
      # GH confirms our new check_run has been created, or rerequested. Update it to "running" and run the linter
      case action
      when :created
        initiate_check_run
      when :rerequested
        initiate_check_run
      end

    end

    'ok' # we have to return _something_ ;)
  end


########## Helpers
#
# These functions are going to help us do some tasks that we don't want clogging up the happy paths above, or
# that need to be done repeatedly. You can add anything you like here, really!
#

  helpers do

    # Create a new Check Run
    def create_check_run
      # First, we need to exchange our JWT for an installation token against the repository that triggered this check
      # suite. This is an important bit of authentication
      token = get_installation_token
      installation_client = Octokit::Client.new(bearer_token: token)

      # Octokit doesn't yet support the Checks API, but it does provide generic HTTP methods we can use!
      # https://developer.github.com/v3/checks/runs/#create-a-check-run
      result = installation_client.post("#{@payload['repository']['url']}/check-runs", {
          accept: 'application/vnd.github.antiope-preview+json', # This header is necessary for beta access to Checks API
          name: 'Awesome CI',
          head_branch: @payload['check_suite']['head_branch'],
          head_sha: @payload['check_suite']['head_sha']
      })

      # Assuming that this notifcation goes through, we would start our actual build run here.
      # To simulate this, we'll wait for GitHub to acknowldge the creation of the run, and update its status to
      # "success" from there.

      result.attrs
    end

    # Start the CI process
    def initiate_check_run
      token = get_installation_token
      installation_client = Octokit::Client.new(bearer_token: token)
      # Update the check run to a success state. We could include other information like line numbers, comments,
      # or other things to help in the case of failure
      # Also, normally, we would make this call when we were actually done with our CI, not as an artificial
      # side effect of a check run being initiated.

      # Octokit doesn't yet support the Checks API, but it does provide generic HTTP methods we can use!
      # https://developer.github.com/v3/checks/runs/#update-a-check-run
      # notice the verb! PATCH!
      result = installation_client.patch(@payload['check_run']['url'], {
          accept: 'application/vnd.github.antiope-preview+json', # This header is necessary for beta access to Checks API
          name: 'Awesome CI',
          status: :in_progress
      })

      # DO IT!
      # TODO should check `result` first

      # TODO should do this async!!

      # Use Git to get the code from the SHA1
      sha = @payload['check_run']['head_sha']
      path = "#{@payload['repository']['full_name']}"
      # make sure path is empty
      FileUtils.rm_rf(path)
      g = Git.clone(@payload['repository']['html_url'], sha, :path => path)
      g.checkout(sha)

      # Run Excellent on the code
      r = Simplabs::Excellent::Runner.new()
      r.check_paths([path])

      # And remove the code
      FileUtils.rm_rf(path)
      # TODO clean up empty folders
      result = r.warnings.empty? ? :success : :failure

      opts = {
          accept: 'application/vnd.github.antiope-preview+json', # This header is necessary for beta access to Checks API
          name: 'Awesome CI',
          status: :completed,
          conclusion: result,
          completed_at: Time.now.utc.iso8601
      }

      if result == :failure
        output = {
            title: 'Awesome CI Warnings',
            summary: 'There were problems with the submitted code',
            annotations: []
        }
        r.warnings.each do |warning|
          # we need to take the local relative path, and extract the repo-relative path
          filename = warning.filename.split("#{path}/#{sha}/")[-1]
          annotation = {
              filename: filename,
              blob_href: "#{@payload['repository']['blobs_url']}/#{filename}".sub('{/sha}', "/#{sha}"),
              start_line: warning.line_number,
              end_line: warning.line_number,
              warning_level: :warning,
              message: warning.message
          }
          output[:annotations].push annotation
        end

        opts[:output] = output
      end

      # Now, mark the check run as complete! And if there are warnings, share them
      result = installation_client.patch(@payload['check_run']['url'], opts)

      result.attrs
    end

    def get_installation_token
      # We include the accept header because GH Apps are still in beta, and this header requests access to that beta
      @client.create_app_installation_access_token(@payload['installation']['id'],
                                                   accept: 'application/vnd.github.machine-man-preview+json')['token']

      # TODO no error checking being done here.
    end


    # This is code for checking the security signature that is included in all legitimate webhooks calls from GitHub
    def check_signature!
      request.body.rewind
      payload_raw = request.body.read # We need the raw text of the body to check the webhook signature
      begin
        @payload = JSON.parse payload_raw
      rescue
        @payload = {}
      end

      # Check X-Hub-Signature to confirm that this webhook was generated by GitHub, and not a malicious third party.
      # The way this works is: We have registered with GitHub a secret, and we have stored it locally in WEBHOOK_SECRET.
      # GitHub will cryptographically sign the request payload with this secret. We will do the same, and if the results
      # match, then we know that the request is from GitHub (or, at least, from someone who knows the secret!)
      # If they don't match, this request is an attack, and we should reject it.
      # The signature comes in with header x-hub-signature, and looks like "sha1=123456"
      # We should take the left hand side as the signature method, and the right hand side as the
      # HMAC digest (the signature) itself.
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, payload_raw)
      halt 401 unless their_digest == our_digest
      @payload
    end

  end


# Finally some logic to let us run this server directly from the commandline, or with Rack
# Don't worry too much about this code ;) But, for the curious:
# $0 is the executed file
# __FILE__ is the current file
# If they are the same—that is, we are running this file directly, call the Sinatra run method
  run! if __FILE__ == $0
end
