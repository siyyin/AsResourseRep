#! /usr/bin/perl
use IO::Socket::INET;
use File::Basename;
use Cwd 'abs_path';
use Sys::Hostname;
use Getopt::Std;
use warnings;
use Encode;

sub IsWinOS ()
{
    #my @OS = POSIX::uname();
    return 1 if ($^O =~ /MSWin32/i);
    return 0;
}

sub IsSolaris ()
{

    return 1 if ($^O =~ /solaris/i);
    return 0;
}

sub Usage(){
	print<<_TEXT;

==================================================
$0
Created Date:2016/05/02 , Author:Evelyn Hsu
Send sign tool command to a signing server
==================================================
[Usage] Sign.pl [-b build_number] <action> <language> <path> [options]
	build_number: Additional option that indicate the build number of the sign file. For build system use only.
	action		: Valid action is:
	               sign  -- sign a file with the specified (AsiaInfo) sign key. (depends on which language was selected)
	               sha2 -- sign a file with  SHA2 (AsiaInfo) sign key.
	               dual --  sign a file with SHA1 (AsiaInfo) certificate then append SHA2 (AsiaInfo) certificate.
		           xcert -- sign a file with X-Cert and the specified (Trendmicro) sign key.
		           xsha2 -- sign a file with X-Cert and the SHA2(Trendmicro) sign key.
		           xdual --  sign a file with X-Cert and the specified (Trendmicro) sign key then append SHA2 (Trendmicro/NTT) certificate.
		           java  -- sign a jar file with company key.
		           aiapk -- sign an apk file with AisaInfo key.
	language	: The language
	path		: Full path to the file that should be signed
	options		: Additional options that should be passed to signtool.exe

[Example]
	AISign.pl sign  en D:\\PCC16\\Output\\test.exe
	AISign.pl sign  en D:\\PCC16\\Output\\test.exe /ph
	AISign.pl sha2 en D:\\PCC16\\Output\\test.exe
	AIsign.pl dual en D:\\PCC16\\Output\\test.exe
	AISign.pl xcert en D:\\PCC16\\Output\\test.sys
	AISign.pl xsha2 en D:\\PCC16\\Output\\test.exe
	AISign.pl xdual en D:\\PCC16\\Output\\test.exe
	AISign.pl java en /home/autobuild/test.jar
	AISign.pl aiapk en /home/autobuild/test.apk


_TEXT

	exit (1);
}

my ($SERVER_IP,$SERVER_PORT,$SERVER_ROOT,$KC,$CSP);
my ($REQUESTOR,$APPROVER,$HANDLER,$REASON,$CERT_TYPE,$VALID_FROM,$VALID_TO,$ORG,$DUAL);
my $SIGN_TOOL;
my $JAVA_SIGN_TOOL;
my $JAVA_STORE_TYPE 		= "nCipher.sworld";
my $SERVER_CACHE_FILE;
my $SERVER_CONFIG_FILE;
my $SIGN_CONFIG_FILE;
my $TIMESTAMP_SERVER 		= "http://timestamp.comodoca.com/authenticode";	#timestamp server URL
my $JAVA_TIMESTAMP_SERVER 	= "http://timestamp.geotrust.com/tsa"; #timestamp server URL for java sign
my $DIGI_TIMESTAMP_SERVER	= "http://timestamp.digicert.com"; #timestamp server URL from digicert(Add new timestamp server in 2015/05/04)
my $SHA2_TIMESTAMP_SERVER 	= "http://sha256timestamp.ws.symantec.com/sha256/timestamp";	#timestamp server URL
my $RETRY_TIMES 		= 2;
my $SIGN_WAIT_TIME 		= 1000 * 60 * 2;		#2 minutes
my $TEST_CERT 			= "ETS_TEST";			#need to update it according to real case
my @WHITE_LIST 			= ("txt", "lib");		#file type could not be signed
my %KC_NAME = (
	"ai"	=> "ai"
);



#prepare build number para
my %opts;
getopts('b:', \%opts);  # -b means: adding buildnubmer option

my $buildnumber;
if( defined $opts{b}){  #defined buildnumber
	$buildnumber = $opts{b};
}else{
	$buildnumber = "NOBUILDNUMBER";
}

#check the para and pretreat space in para
my ($action, $lang, $filepath, @options) = @ARGV;
if( ! $action || ! $lang || ! $filepath ) {
	Usage();
}

my @item;
foreach my $i (@options){
	$i = "\"".$i."\"";
	$i =~ s/\s/\&nbsp\;/g;
	push @item, $i;
}
@options = @item;

#skip the sign request if file extension is in @WHITE_LIST
my $ext = ($filepath =~ m/([^.]+)$/)[0];

foreach (@WHITE_LIST){
	if($ext eq $_){
		print "File type with extension $ext not supported\n";
		exit 1;
	}
}

my $workDir = InitScript();
my $PDG_TEST_CERT = "$workDir\\test.pfx";	#test cert provided by PDG
my $Server_from_cache = 0;

#get candidate sign server
print "Begin to try to fetch the most connective sever in the cache file.\n";
if(IsWinOS()){
	$SERVER_CACHE_FILE = "$workDir\\server_cache.txt";
}else{
	$SERVER_CACHE_FILE = "$workDir/server_cache.txt";
}

if(-e "$SERVER_CACHE_FILE"){
	print "There is server_cache.txt file in $workDir.\n";
	open SEVERCACHELIST, "$SERVER_CACHE_FILE" or print "cannot find $SERVER_CACHE_FILE";
	while(<SEVERCACHELIST>){
		my $line = $_;
		chomp $line;
		next if $line =~ /^\s*$/;

		($SERVER_IP,$SERVER_PORT,$SERVER_ROOT,$CSP)=split /\|/,$line;
		print "Find Sever in server_cache.txt:$line\n";
	}
	close SEVERCACHELIST or print "Cannot close $SERVER_CACHE_FILE";
}else{
	print "Cannot find server_cache.txt\n";
}
print "End to fetch the most connective sever in the cache file.\n";

Label1:
if((!$SERVER_IP)||(!$SERVER_PORT)||(!$SERVER_ROOT)||(!$CSP)){
	print "Begin to iterate the server list to fetch the most connective Server and Port...\n";
	if(IsWinOS()){
		$SERVER_CONFIG_FILE = "$workDir\\server.cfg"
	}else{
		$SERVER_CONFIG_FILE = "$workDir\/server.cfg"
	}
	open SEVERLIST, "$SERVER_CONFIG_FILE" or die "cannot find server.cfg";
	my $reply_time = 10000;
	while(<SEVERLIST>){
		my $line=$_;
		chomp $line;
		next if $line=~/^\s*$/;

		my $ip_port_tmp;
		my $server_ip_tmp;
		my $server_port_tmp;
		my $server_root_tmp;
		my $csp_tmp;
		($ip_port_tmp,$server_root_tmp,$csp_tmp)=split /\|/,$line;
		($server_ip_tmp,$server_port_tmp) = split ":",$ip_port_tmp;

		my $t;
		my $minT;
		my @result;
		my $pattern;
		if(IsWinOS()){
			my $pingPath = $ENV{'SYSTEMROOT'};
			$pingPath .= "\\"."system32"."\\"."ping.exe";
			@result=`$pingPath -n 2 $server_ip_tmp`;
			$pattern = "Reply from.*: bytes=32 time.(.+)ms.*";
		}elsif(IsSolaris()){
			@result = `ping -s $server_ip_tmp 500 2`;
			$pattern = ".*time=(.+) ms.*";
		}else{
			@result = `ping -c 2 $server_ip_tmp`;
			$pattern = ".*time=(.+) ms.*";
		}
		for(@result){
			if(/$pattern/){
				$t=$1;
				if($t<$reply_time){
					$minT=$t;
				}
			}
		}
		if((defined $minT)&&$reply_time>$minT){
				$reply_time = $minT;
				$SERVER_IP = $server_ip_tmp;
				$SERVER_PORT = $server_port_tmp;
				$SERVER_ROOT = $server_root_tmp;
				$CSP = $csp_tmp;
		}
	}
	if((!$SERVER_IP)||(!$SERVER_PORT)||(!$SERVER_ROOT)||(!$CSP)){
		die "cannot find an availabel sign server!\n";
	}
	#store sign server information to cache file
	print "The final sign server:$SERVER_IP,$SERVER_PORT\n";
	print "Begin to store the most connective server to server_cache.txt\n";
	open SEVERCACHELIST, "> $SERVER_CACHE_FILE" or print "cannot find $SERVER_CACHE_FILE";
	my $line_tmp = "";
	$line_tmp = join("|",$SERVER_IP,$SERVER_PORT,$SERVER_ROOT,$CSP);
	print "$line_tmp\n";
	print SEVERCACHELIST $line_tmp;
	close SEVERCACHELIST or print "Cannot close $SERVER_CACHE_FILE";
	print "Finish store the most connective server to server_cache.txt\n";
	print "Finish iterate the server list to fetch the most connective Server and Port...\n";
	close SEVERLIST or print "Cannot close $SERVER_CONFIG_FILE\n";
	$Server_from_cache = 0;
}else{
	$Server_from_cache = 1;
}
#decide to use test cert or normal cert, use offical cert if sign.cfg does not exist
if(IsWinOS()){
	$SIGN_CONFIG_FILE = "$workDir\\sign.cfg"
}else{
	$SIGN_CONFIG_FILE = "$workDir\/sign.cfg"
}
if(-e "$SIGN_CONFIG_FILE"){
	print "There is sign.cfg file in $workDir.\n";
	open SIGNCONFIG, "$SIGN_CONFIG_FILE" or print "cannot find $SIGN_CONFIG_FILE";
	while(<SIGNCONFIG>){
		my $line=$_;
		chomp $line;
		next if $line=~/^\s*$/;

		if($line=~ m/REQUESTOR\s*=\s*(.*)/){
			$REQUESTOR = $1;
		}elsif($line=~ m/APPROVER\s*=\s*(.*)/){
			$APPROVER = $1;
		}elsif($line=~ m/HANDLER\s*=\s*(.*)/){
			$HANDLER = $1;
		}elsif($line=~ m/REASON\s*=\s*(.*)/){
			$REASON = $1;
			$REASON =~ s/\"//g;	#remove \" in string as we'll add \" to include the whole string later
		}elsif($line=~ m/CERT_TYPE\s*=\s*(.*)/){
			$CERT_TYPE = $1;
		}elsif($line=~ m/VALID_FROM\s*=\s*(.*)/){
			$VALID_FROM = $1;
		}elsif($line=~ m/VALID_TO\s*=\s*(.*)/){
			$VALID_TO = $1;
		}elsif($line=~ m/ORG\s*=\s*(.*)/){
			$ORG = $1;
		}elsif($line=~ m/DUAL\s*=\s*(.*)/){
			$DUAL = $1;
		}else{
			print "Invalid config,discard it!\n";
		}
	}
	close SIGNCONFIG;
	if((!$REQUESTOR)||(!$APPROVER)||(!$HANDLER)||(!$REASON)||(!$CERT_TYPE)||(!$VALID_FROM)||(!$VALID_TO)||(!$ORG)||(!$DUAL)){
		die "Neccessary item lost in config file!\n";
	}
}else{

	$REQUESTOR = "BUILD";
	$APPROVER = "BUILD";
	$HANDLER = "BUILD";
	$REASON = "BUILD";
	$CERT_TYPE = "NORMAL";
	$VALID_FROM = "1900-1-1";
	$VALID_TO = "9999-12-12";
	$ORG = "TREND";
	$DUAL = "N";

}

#get container name
if(IsWinOS()){
	$CERT_CONTAINER_CONFIG = "$workDir\\cert_container.cfg"
}else{
	$CERT_CONTAINER_CONFIG = "$workDir\/cert_container.cfg"
}
if(-e "$CERT_CONTAINER_CONFIG"){
	print "There is cert_container.cfg file in $workDir.\n";
	open CERTCONTAINERCONFIG, "$CERT_CONTAINER_CONFIG" or print "cannot find $CERT_CONTAINER_CONFIG";
	while(<CERTCONTAINERCONFIG>){
		my $line=$_;
		chomp $line;
		next if $line=~/^\s*$/;

		if($line=~ m/EVCONTAINER_NAME\s*=\s*(.*)/){
			$EVCONTAINER_NAME = $1;
		}else{
			print "Invalid config,discard it!\n";
		}


	}
	close CERTCONTAINERCONFIG;
	if((!$EVCONTAINER_NAME)){
		die "Cannot found container name.\n";
	}
}

if(IsWinOS()){
	$SEARCH_CERT_CONFIG = "$workDir\\search_cert_keyword.cfg"
}else{
	$SEARCH_CERT_CONFIG = "$workDir\/search_cert_keyword.cfg"
}
if(-e "$SEARCH_CERT_CONFIG"){
	print "There is search_cert_keyword.cfg file in $workDir.\n";
	open SEARCHCERTCONFIG, "$SEARCH_CERT_CONFIG" or print "cannot find $SEARCH_CERT_CONFIG";
	while(<SEARCHCERTCONFIG>){
		my $line=$_;
		chomp $line;
		next if $line=~/^\s*$/;

		if($line=~ m/AICERT\s*=\s*(.*)/){
			$AICERT = $1;
		}else{
			print "Invalid config,discard it!\n";
		}


	}
	close SEARCHCERTCONFIG;
	if((!$AICERT)){
		die "Cannot found search condition.\n";
	}
}

my $host = hostname();
my $LOCAL_IP = inet_ntoa( scalar gethostbyname( $host || 'localhost' ) );

#connect to sign server via socket
my ($buffer,$socket,@socketstore,$status,$getsocket);
my ($buffersha1,$socketsha1,@socketstoresha1,$statussha1,$getsocketsha1);
my $count = 0;		#count of retry times
RETRY:
eval
{
	$socket = IO::Socket::INET->new(PeerAddr => $SERVER_IP,
					PeerPort => $SERVER_PORT,
					Proto    => 'tcp') || die "\tCANNOT connect to $SERVER_IP:$SERVER_PORT\n";
};

RETRYSHA1:
eval
{
	$socketsha1 = IO::Socket::INET->new(PeerAddr => $SERVER_IP,
					PeerPort => $SERVER_PORT,
					Proto    => 'tcp') || die "\tCANNOT connect to $SERVER_IP:$SERVER_PORT\n";
};
if ($@){
	print $@;
	if($Server_from_cache){
		print "The server($SERVER_IP:$SERVER_PORT) is from server_cache.txt, so try to fetch the most connective server from server.txt and try again\n";
		($SERVER_IP,$SERVER_PORT,$SERVER_ROOT)=(undef,undef,undef);
		goto Label1;
	}else{
		exit(1);
	}

}else{
	my $uncFilePath = GetUNCPath($filepath);
	my $signCmd;
	my $signSHA1Cmd;
	my $certName;
	my $certPath = "$SERVER_ROOT\\Cert\\ai.cer";
	$SIGN_TOOL = "$SERVER_ROOT\\signtool\\x64\\signtool.exe";
	$JAVA_SIGN_TOOL = "java \-DignorePassphrase=true  sun.security.tools.JarSigner";


	if ((uc($CERT_TYPE) eq "TEST") || !IS_VALID_DATE($VALID_FROM,$VALID_TO)){
		if (-e "$PDG_TEST_CERT"){
			my $uncCertPath = GetUNCPath($PDG_TEST_CERT);
			if (uc($action) eq "SIGN"){
				$signCmd = "$SIGN_TOOL sign /f $uncCertPath /t $TIMESTAMP_SERVER /v @options ";
			}else{
				print "$action not supported!\n";
				Usage();
			}
		}else{
			if (uc($action) eq "SIGN"){
				$signCmd = "$SIGN_TOOL sign /n $TEST_CERT /t $TIMESTAMP_SERVER /v @options ";
			}else{
				print "$action not supported!\n";
				Usage();
			}
		}
		$signCmd .= $uncFilePath;
		$signCmd .= " $buildnumber";
		$signCmd .= " -LOG";
		$signCmd .= " REQUESTOR=$REQUESTOR";
		$signCmd .= " APPROVER=$APPROVER";
		$signCmd .= " HANDLER=$HANDLER";
		$signCmd .= " REASON=\"$REASON\"";
		$signCmd .= " CERT_TYPE=TEST";
		$signCmd .= " CLIENT=$LOCAL_IP";
		$signCmd .= " BUILDNUMBER=$buildnumber";
		$signCmd .= " ORG=$ORG";
		$signCmd .= " DUAL=$DUAL";
		print "SignCmd:$signCmd\n";
	}elsif ((uc($CERT_TYPE) eq "NORMAL") && IS_VALID_DATE($VALID_FROM,$VALID_TO)){
		$KC = GetKCName($action);
		my $sha1Cert = "F94E9B56E135F89CC882998BA8C595FBE560DFD0";
		my $sha2Cert = "d674221fb462e787b00df9783f56f64e76d77fce";
		if (uc($action) eq "SIGN"){
			$signCmd = "$SIGN_TOOL sign /sha1 $sha1Cert /t $TIMESTAMP_SERVER /i DigiCert /v @options ";
		}elsif (uc($action) eq "SHA2"){
			$signCmd = "$SIGN_TOOL sign /sha1 $sha2Cert /tr $SHA2_TIMESTAMP_SERVER /i DigiCert /v /fd sha256 /td sha256 @options ";
		}elsif (uc($action) eq "DUAL"){
			$signSHA1Cmd = "$SIGN_TOOL sign /sha1 $sha1Cert /t $TIMESTAMP_SERVER /i DigiCert /v @options ";
			$signCmd = "$SIGN_TOOL sign /as /sha1 $sha2Cert /tr $SHA2_TIMESTAMP_SERVER /i DigiCert /v /fd sha256 /td sha256 @options ";
		}elsif (uc($action) eq "XCERT"){
			$signCmd = "$SIGN_TOOL sign /sha1 $sha1Cert /ac \"$SERVER_ROOT\\X-Cert\\MS_xs_WS\.crt\" /t $TIMESTAMP_SERVER /i DigiCert /v @options ";
		}elsif (uc($action) eq "XSHA2"){
			$signCmd = "$SIGN_TOOL sign /sha1 $sha2Cert /ac \"$SERVER_ROOT\\X-Cert\\MS_xs_WS\.crt\" /fd sha256 /td sha256  /tr $SHA2_TIMESTAMP_SERVER /i DigiCert /v @options ";
		}elsif (uc($action) eq "XDUAL"){
			$signSHA1Cmd = "$SIGN_TOOL sign /sha1 $sha1Cert /ac \"$SERVER_ROOT\\X-Cert\\MS_xs_WS\.crt\" /t $TIMESTAMP_SERVER /i DigiCert /v @options ";
			$signCmd = "$SIGN_TOOL sign /as /sha1 $sha2Cert /ac \"$SERVER_ROOT\\X-Cert\\MS_xs_WS\.crt\" /fd sha256 /td sha256  /tr $SHA2_TIMESTAMP_SERVER /i DigiCert /v @options ";
		}elsif (uc($action) eq "AIAPK"){
			$ORG = "ASIAINFO";
			$signCmd = "$JAVA_SIGN_TOOL -tsa $JAVA_TIMESTAMP_SERVER -storetype jceks -keystore xxxx -storepass xxxx -keypass xxxx  -verbose ";
		}elsif (uc($action) eq "JAVA"){
			$ORG = "AISEJAVA";
			$signCmd = "$JAVA_SIGN_TOOL -tsa $JAVA_TIMESTAMP_SERVER -storetype JKS -keystore xxxx -storepass xxxx -keypass xxxx -providerName SUN -verbose ";
		}else{
			print "$action not supported!\n";
			Usage();
		}

		if (($action) eq "xdual" || ($action) eq "dual" ){
			$signSHA1Cmd  .= $uncFilePath;
			$signSHA1Cmd .= " $buildnumber";
			$signSHA1Cmd .= " -LOG";
			$signSHA1Cmd .= " REQUESTOR=$REQUESTOR";
			$signSHA1Cmd .= " APPROVER=$APPROVER";
			$signSHA1Cmd .= " HANDLER=$HANDLER";
			$signSHA1Cmd .= " REASON=\"$REASON\"";
			$signSHA1Cmd .= " CERT_TYPE=NORMAL";
			$signSHA1Cmd .= " CLIENT=$LOCAL_IP";
			$signSHA1Cmd .= " BUILDNUMBER=$buildnumber";
			$signSHA1Cmd .= " ORG=$ORG";
			$signSHA1Cmd .= " DUAL=Y";

			print "SignSHA1Cmd:$signSHA1Cmd\n";
		}


		$signCmd .= $uncFilePath;
		$signCmd .= " $buildnumber";
		$signCmd .= " -LOG";
		$signCmd .= " REQUESTOR=$REQUESTOR";
		$signCmd .= " APPROVER=$APPROVER";
		$signCmd .= " HANDLER=$HANDLER";
		$signCmd .= " REASON=\"$REASON\"";
		$signCmd .= " CERT_TYPE=NORMAL";
		$signCmd .= " CLIENT=$LOCAL_IP";
		$signCmd .= " BUILDNUMBER=$buildnumber";
		$signCmd .= " ORG=$ORG";
		$signCmd .= " DUAL=$DUAL";

		print "SignCmd:$signCmd\n";
	}

	#send sign command to sign server

	if (($action) eq "xdual" || ($action) eq "dual" ){
		print "begin send signcmd\n";
		print $socketsha1 "STARTSIGN\n";
		my $new = $socketsha1->recv($buffersha1,1024);
		print "Recieved remote massage: $buffersha1.\n";
		print "Dual Sign : Sign SHA1 certificate.... \n";
		print $socketsha1 $signSHA1Cmd."\n";
		push (@socketstoresha1,$socketsha1);         #put socket in the array for later to reference
		print "Waiting for remote machine...\n";
	 	while (defined($getsocketsha1 = shift(@socketstoresha1))){	#get each one of the socket and wait for their report
			print "Dual Sign : Sign SHA1 certificate $getsocketsha1 ";
			my $bufsha1;
			$getsocketsha1->recv($bufsha1,1024*5);
			#print "Return massage: $bufsha1 \n";
			print $getsocketsha1 "I have got your report!\n";
			close $getsocketsha1;
			$statussha1 = ( $bufsha1 =~ m/STATUS (\d+)/ ) ? $1 : 1;
			#print "Status now is $statussha1\n";
			#print "Exit Status [$statussha1]\n";
			#retry 3 times if sign failed
			if ($statussha1 != 0){
				$count++;
				if ($count < $RETRY_TIMES || $statussha1 == 2){
					goto RETRYSHA1;
				}else{
					print "Return massage: $bufsha1 \n";
					print "Status now is $statussha1\n";
					print "Exit Status [$statussha1]\n";
					goto THESHA1END;

				}
			}else{
				print "Return massage: $bufsha1 \n";
				print "Status now is $statussha1\n";
				print "Exit Status [$statussha1]\n";
			}
			if ($statussha1 == 0){
				print "SignCmd:$signCmd\n";
				print "begin send signcmd\n";
				print $socket "STARTSIGN\n";
				my $new = $socket->recv($buffer,1024);
				print "Recieved remote massage: $buffer.\n";
				print "Dual Sign : Append SHA2 certificate";
				print $socket $signCmd."\n";
				push (@socketstore,$socket);         #put socket in the array for later to reference
				print "Waiting for remote machine...\n";
				while (defined($getsocket = shift(@socketstore))){	#get each one of the socket and wait for their report
					print "Dual Sign : Append SHA2 certificate $getsocketsha1 ";
					my $buf;
					$getsocket->recv($buf,1024*5);
					#print "Return massage: $buf \n";
					print $getsocket "I have got your report!\n";
					close $getsocket;
					$status = ( $buf =~ m/STATUS (\d+)/ ) ? $1 : 1;
					#print "Status now is $status\n";
					#print "Exit Status [$status]\n";
					#retry 3 times if sign failed
					if ($status != 0){
						$count++;
						if ($count < $RETRY_TIMES || $status == 2){
							goto RETRY;
						}else{
							print "Return massage: $buf \n";
							print "Status now is $status\n";
							print "Exit Status [$status]\n";
						}
					}else{
						print "Return massage: $buf \n";
						print "Status now is $status\n";
						print "Exit Status [$status]\n";

					}
					goto THESHA1END;
				}
			}
			goto THESHA1END;


		}
		THESHA1END:
		eval{
			exit($status);
			exit($statussha1);

		}

	}else{

		print "SignCmd:$signCmd\n";
		print "begin send signcmd\n";
		print $socket "STARTSIGN\n";
		my $new = $socket->recv($buffer,1024);
		print "Recieved remote massage: $buffer.\n";
		print $socket $signCmd."\n";
		push (@socketstore,$socket);         #put socket in the array for later to reference
		print "Waiting for remote machine...\n";
		while (defined($getsocket = shift(@socketstore))){	#get each one of the socket and wait for their report
			my $buf;
			$getsocket->recv($buf,1024*5);
			#print "Return massage: $buf \n";
			print $getsocket "I have got your report!\n";
			close $getsocket;
			$status = ( $buf =~ m/STATUS (\d+)/ ) ? $1 : 1;
			#print "Status now is $status\n";
			#print "Exit Status [$status]\n";
			#retry 3 times if sign failed
			if ($status != 0){
				$count++;
				if ($count < $RETRY_TIMES || $status == 2){
					goto RETRY;
				}else{
					print "Return massage: $buf \n";
					print "Status now is $status\n";
					print "Exit Status [$status]\n";
				}
			}else{
				print "Return massage: $buf \n";
				print "Status now is $status\n";
				print "Exit Status [$status]\n";
			}
			goto THEEND;
		}
	}

THEEND:
	exit($status);
}

sub GetUNCPath{
	my ($path) = @_;
    my $orgPath="";
	if ($path =~ /^\\\\/){
		$path =~ s|\s|*|g;
		return $path;
	}
	$path = abs_path($path);
	if($@){
		print $@;
		return "-1";
	}
	if ( ! $path ) {
		return "";
	}
	$path =~ s|/|\\|g;
	$orgPath = $path;


	print "start check filename: "."$orgPath"."\n";

	#check file exist
	if (not -e $orgPath){
		print $orgPath." do not exist!\n";
	}

	#check is path
	if (-d $orgPath){
		$comment = $orgPath." is path not file!\n";
		print $comment;
	}

	#check file write permission
	if (!-w $orgPath){
		print $orgPath." write permission denie\n";
	}


	my $filesize = -s $orgPath;
	print "file size: ". $filesize. "\n";


	if (IsWinOS()){
		# Change from C:\Test.exe to \C$\Test.exe
		if ( $path =~ m/^([A-Za-z]):(.+)/ ){
			$path = "\\" . $1 . "\$" . $2;
		}
	}elsif(IsSolaris()){
		#remove \export\home in the path
		if ( $path =~ m/^\\export\\home(.+)/ ){
			$path = $1;
		}
	}else{
		#remove \home in the path
		if ( $path =~ m/^\\home(.+)/ ){
			$path = $1;
		}
	}

	$path = "\\\\$LOCAL_IP" . $path;
	$path =~ s|\s|*|g;

	return $path;
}


sub InitScript{
	my $ownPath = dirname( abs_path($0) );
	if (IsWinOS()){
		$ownPath =~ s|/|\\|g;
	}
	return $ownPath;
}

sub GetKCName{
	#support Trendmicro & NTT key
	my ($lang) = @_;

	return $KC_NAME{"ai"};
}

sub IS_VALID_DATE{
	my ($valid_begin_time,$valid_end_time) = @_;
	if (!$valid_begin_time || !$valid_end_time){
		die "Both $VALID_FROM and $VALID_TO are needed!\n";
	}
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime(time);
	my ($valid_begin_year,$valid_begin_month,$valid_begin_day) = split /-/,$valid_begin_time;
	my ($begin_time,$end_time,$current_time);
	$begin_time = $valid_begin_year * 365 + $valid_begin_month * 31 + $valid_begin_day;
	$current_time = ($year + 1900) * 365 + ($mon + 1) * 31 + $mday;
	my ($valid_end_year,$valid_end_month,$valid_end_day) = split /-/,$valid_end_time;
	$end_time = $valid_end_year * 365 + $valid_end_month * 31 + $valid_end_day;
	if (($current_time >= $begin_time) && ($current_time <= $end_time)){
		return 1;
	}else{
		return 0;
	}
}

