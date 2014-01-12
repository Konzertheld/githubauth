<?php
namespace Habari;

class GithubAuth extends Plugin
{
	private $service = 'GitHub';
	
	/**
	 * Outputs the "configure" button on the plugin page.
	 */
	public function filter_plugin_config( $actions, $plugin_id ) {
		if ( $plugin_id == $this->plugin_id() ) {
			return array( _t('Configure') );
		}
		return $actions;
	}
	
	/*
	 * Add config
	 */
	public function action_plugin_ui( $plugin_id, $action )
	{
		if ($plugin_id == $this->plugin_id() )
		{
			switch($action)
			{
				case _t('Configure'):
					$form = new FormUI( __CLASS__ );
					$form->append(FormControlLabel::wrap(_t( 'Redirect URI (relative to your domain) - defaults to "github_oauth_callback" if left empty', __CLASS__ ), FormControlText::create('redirect_uri', __CLASS__ . '__redirect_uri')));
					$form->append(FormControlLabel::wrap(_t( 'Client ID', __CLASS__ ), FormControlText::create('client_id', __CLASS__ . '__client_id')));
					$form->append(FormControlLabel::wrap(_t( 'Client Secret', __CLASS__ ), FormControlText::create('client_secret', __CLASS__ . '__client_secret')));
					$form->append(FormControlLabel::wrap(_t( 'Scopes (comma separated)', __CLASS__ ), FormControlText::create('scope', __CLASS__ . '__scope')));
					$form->append(FormControlSubmit::create('save')->set_caption('Save'));
					$form->out();
					break;
			}
		}
	}
	
	/*
	 * Add rewrite rule to catch the authentication result
	 * Default to github_oauth_callback if not set
	 */
	public function filter_rewrite_rules($rules)
    {
		$opts = Options::get_group( __CLASS__ );
		$callback = isset($opts['redirect_uri']) && !empty($opts['redirect_uri']) ? $opts['redirect_uri'] : "github_oauth_callback";
		$rules[] = RewriteRule::create_url_rule('"' . $callback . '"', 'PluginHandler', 'github_oauth_callback');
        return $rules;
    }
	
	/*
	 * Add GitHub to the list of social services providing the socialauth feature
	 */
	public function filter_socialauth_services($services = array())
	{
		$opts = Options::get_group( __CLASS__ );
		if(isset($opts['client_id']) && isset($opts['client_secret'])) {
			// If those are not set, it's of no use to make this plugin public
			$services[] = $this->service;
		}
		return $services;
	}
	
	/*
	 * Provide auth link to the theme
	 * @param string $service The service / social network the link is requested for.
	 * @param array Accepts values for overriding the global options redirect_uri and scope and additional state, a value that will be roundtripped through the Google servers until returned with the redirect URI
	 */
	public function theme_socialauth_link($theme, $service, $paramarray = array())
	{
		if($service == $this->service) {
			$opts = Options::get_group( __CLASS__ );
			$url = "https://github.com/login/oauth/authorize?";
			
			if(isset($paramarray['scope'])) {
				$url .= "scope=" . $paramarray['scope'];
			}
			else if(isset($opts['scope'])) {
				$url .= "scope=" . $opts['scope'];
			}
			
			if(isset($paramarray['redirect_uri'])) {
				$url .= "&redirect_uri=" . $paramarray['redirect_uri'];
			} else {
				$url .= "&redirect_uri=" . URL::get('github_oauth_callback');
			}

			if(isset($paramarray['state'])) {
				$url .= "&state=" . $paramarray['state'];
			}
			
			if(isset($opts['client_id'])) {
				$url .= "&client_id=" . $opts['client_id'];
			}
			else {
				// The client id is the one obligatory argument
				return false;
			}
			
			return $url;
		}
	}
	
	/*
	 * Handle the authentication result
	 */
	public function action_plugin_act_github_oauth_callback($handler)
	{
		$code = $_GET['code'];
		$state = $_GET['state'];
		$opts = Options::get_group(__CLASS__);
		
		// Exchange code for token
		$request = new RemoteRequest("https://github.com/login/oauth/access_token", "POST");
		$request->set_postdata(array("code" => $code, "client_id" => $opts['client_id'], "client_secret" => $opts['client_secret']));
		$request->add_header('Accept: application/json');
		$request->execute();
		
		if ( ! $request->executed() ) {
			throw new XMLRPCException( 16 );
		}
		$json_response = $request->get_response_body();
		$jsondata = json_decode($json_response);
		$token = $jsondata->{'access_token'};
		
		// Offer the token to plugins that want to do something with the authenticated user
		Plugins::act('githubauth_token', $token);
		
		// Get user info. Wrap in try-catch because we don't know if the userinfo is available
		try {
			$request = new RemoteRequest("https://api.github.com/user?access_token=$token");
			$request->execute();
			if ( ! $request->executed() ) {
				throw new XMLRPCException( 16 );
			}
			$json_response = $request->get_response_body();
			$jsondata = json_decode($json_response);
			
			// The following is important, because it's part of the "socialauth" feature API
			$userdata = array("id" => $jsondata->id);
			
			if(isset($jsondata->name)) {
				$userdata['name'] = $jsondata->name;
			} else {
				$userdata['name'] = $jsondata->login;
			}
			
			if(isset($jsondata->avatar_url)) {
				$userdata["portrait_url"] = $jsondata->avatar_url;
			}

			if(isset($jsondata->email) && !empty($jsondata->email)) {
				$userdata['email'] = $jsondata->email;
			} else {
				// no public mail, receive mail via mail API
				// currently does not work (API not found)
				/*$request = new RemoteRequest("https://api.github.com/user/emails?access_token=$token");
				$request->execute();
				if ( ! $request->executed() ) {
					throw new XMLRPCException( 16 );
				}
				$json_response = $request->get_response_body();
				$jsondata = json_decode($json_response);
				*/
				// TO BE CONTINUED
			}
			
			// Pass the identification data to plugins
			Plugins::act('socialauth_identified', $this->service, $userdata, $state);
		} catch(Exception $e) {
			// don't care if it fails, the only consequence is that action_social_auth will not be triggered, which is correct
		}
	}
}
?>