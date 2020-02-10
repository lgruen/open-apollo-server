# open-apollo server component

This is an implementation of the server component for the
[Apollo](https://github.com/KhaosT/open-apollo) Spotify player
that implements streaming on the Apple Watch.

Special thanks to @KhaosT for making this player available as open source and
to @rafaelmaeuer for pointing me in the right direction for the server
implementation.

## Prerequisites

To run this, you'll need to have
[Google Cloud Functions](https://cloud.google.com/functions)
configured.

You'll need to have a Spotify app registered at
https://developer.spotify.com/dashboard/applications.

Enter `open-apollo://callback` under "Redirect URIs" and `app.awas.Apollo`
under "Bundle IDs".

Note your client ID and secret, you'll need it below.

## Installing the server endpoints

Set the following environment variables: `SPOTIFY_CLIENT_ID`,
`SPOTIFY_CLIENT_SECRET`.

Select a nearby region to keep latency low, replacing `$REGION` below:

```
gcloud config set functions/region $REGION
```

The `replace` statement in the `go.mod` file doesn't seem to work with the way
Cloud Functions are compiled for deployment, therefore run the following to
create a `vendor` directory:

```
go mod vendor
```

Finally, deploy the various endpoints:

```
# /token
gcloud functions deploy token --entry-point Token --runtime go113 --trigger-http --set-env-vars SPOTIFY_CLIENT_ID=$SPOTIFY_CLIENT_ID,SPOTIFY_CLIENT_SECRET=$SPOTIFY_CLIENT_SECRET

# /refresh
gcloud functions deploy refresh --entry-point Refresh --runtime go113 --trigger-http --set-env-vars SPOTIFY_CLIENT_ID=$SPOTIFY_CLIENT_ID,SPOTIFY_CLIENT_SECRET=$SPOTIFY_CLIENT_SECRET

# /track
gcloud functions deploy track --entry-point Track --runtime go113 --trigger-http

# /tracks
gcloud functions deploy tracks --entry-point Tracks --runtime go113 --trigger-http

# /storage-resolve
gcloud functions deploy storage-resolve --entry-point StorageResolve --runtime go113 --trigger-http
```

## Configuring open-apollo

Clone the [open-apollo](https://github.com/KhaosT/open-apollo) repository.

Copy the base URL for your endpoints
(`https://$REGION-$PROJECT.cloudfunctions.net/`) to the
`open-apollo/Apollo/Configuration/DefaultServiceConfiguration.swift` file, for
both `YOUR_SERVICE_URL` and `YOUR_TRACK_SERVICE_URL`.

In the `open-apollo/Apollo/Configuration/SpotifyAuthorizationContext.swift`
file, enter your client ID as `YOUR_CLIENT_ID`, `open-apollo` as the
`callbackURLScheme`, and `open-apollo://callback` as the `redirect_uri`.

In your Apollo Xcode project, in the `Info` settings for the `Apollo` target,
make sure to add `open-apollo` as "URL Schemes" in the "URL Types" section.

Compile and run the Apollo app. If you have trouble installing the Apollo Watch
app through the iOS Watch app, try running the `Watch` target directly from
Xcode.

If you get any errors, the Cloud Function logs might contain some clues.
