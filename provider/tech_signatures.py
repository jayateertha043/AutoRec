tech_signatures={
    "apps": {
      "1C-Bitrix": {
        "cats": [
          1
        ],
        "headers": {
          "Set-Cookie": "BITRIX_",
          "X-Powered-CMS": "Bitrix Site Manager"
        },
        "html": "(?:<link[^>]+components/bitrix|(?:src|href)=\"/bitrix/(?:js|templates))",
        "implies": "PHP",
        "script": "1c-bitrix"
      },
      "91App": {
        "cats": [
          6
        ],
        "script": "https\\:\\/\\/track\\.91app\\.io\\/track\\.js\\?"
      },
      "3dCart": {
        "cats": [
          1,
          6
        ],
        "cookies": {
          "3dvisit": ""
        },
        "headers": {
          "X-Powered-By": "3DCART"
        },
        "script": "(?:twlh(?:track)?\\.asp|3d_upsell\\.js)"
      },
      "A-Frame": {
        "cats": [
          25
        ],
        "html": "<a-scene[^<>]*>",
        "implies": "three.js",
        "js": {
          "AFRAME.version": "^(.+)$\\;version:\\1"
        },
        "script": "/?([\\d.]+)?/aframe(?:\\.min)?\\.js\\;version:\\1"
      },
      "AD EBiS": {
        "cats": [
          10
        ],
        "html": [
          "<!-- EBiS contents tag",
          "<!--EBiS tag",
          "<!-- Tag EBiS",
          "<!-- EBiS common tag"
        ]
      },
      "AOLserver": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "AOLserver/?([\\d.]+)?\\;version:\\1"
        }
      },
      "AT Internet Analyzer": {
        "cats": [
          10
        ],
        "js": {
          "ATInternet": "",
          "xtsite": ""
        }
      },
      "AT Internet XiTi": {
        "cats": [
          10
        ],
        "js": {
          "xt_click": ""
        },
        "script": "xiti\\.com/hit\\.xiti"
      },
      "AWStats": {
        "cats": [
          10
        ],
        "implies": "Perl",
        "meta": {
          "generator": "AWStats ([\\d.]+(?: \\(build [\\d.]+\\))?)\\;version:\\1"
        }
      },
      "Accelerated Mobile Pages": {
        "cats": [
          12
        ],
        "html": "<html[^>]* (?:amp|⚡)"
      },
      "Azure": {
        "cats": [
          62
        ],
        "headers": {
          "azure-regionname": "",
          "azure-sitename": "",
          "azure-slotname": "",
          "azure-version": ""
        },
        "cookies": {
          "ARRAffinity": "",
          "TiPMix": ""
        }
      },
      "Azure CDN": {
        "cats": [
          31
        ],
        "headers": {
          "server": "^(?:ECAcc|ECS|ECD)",
          "X-EC-Debug": ""
        }
      },
      "Acquia Cloud": {
        "cats": [
          62
        ],
        "headers": {
          "X-AH-Environment": "^\\w+$"
        },
        "implies": [
          "Drupal\\;confidence:95",
          "Apache",
          "Percona",
          "Amazon EC2"
        ]
      },
      "Act-On": {
        "cats": [
          32
        ],
        "js": {
          "ActOn": ""
        }
      },
      "AdInfinity": {
        "cats": [
          36
        ],
        "script": "adinfinity\\.com\\.au"
      },
      "AdRiver": {
        "cats": [
          36
        ],
        "html": "(?:<embed[^>]+(?:src=\"https?://mh\\d?\\.adriver\\.ru/|flashvars=\"[^\"]*(?:http:%3A//(?:ad|mh\\d?)\\.adriver\\.ru/|adriver_banner))|<(?:(?:iframe|img)[^>]+src|a[^>]+href)=\"https?://ad\\.adriver\\.ru/)",
        "js": {
          "adriver": ""
        },
        "script": "(?:adriver\\.core\\.\\d\\.js|https?://(?:content|ad|masterh\\d)\\.adriver\\.ru/)"
      },
      "AdRoll": {
        "cats": [
          36
        ],
        "js": {
          "adroll_adv_id": "",
          "adroll_pix_id": ""
        },
        "script": "(?:a|s)\\.adroll\\.com"
      },
      "Adcash": {
        "cats": [
          36
        ],
        "js": {
          "SuLoaded": "",
          "SuUrl": "",
          "ac_bgclick_URL": "",
          "ct_nOpp": "",
          "ct_nSuUrl": "",
          "ct_siteunder": "",
          "ct_tag": ""
        },
        "script": "^[^\\/]*//(?:[^\\/]+\\.)?adcash\\.com/(?:script|ad)/",
        "url": "^https?://(?:[^\\/]+\\.)?adcash\\.com/script/pop_"
      },
      "AddShoppers": {
        "cats": [
          5
        ],
        "script": "cdn\\.shop\\.pe/widget/"
      },
      "AddThis": {
        "cats": [
          5
        ],
        "js": {
          "addthis": ""
        },
        "script": "addthis\\.com/js/"
      },
      "AddToAny": {
        "cats": [
          5
        ],
        "js": {
          "a2apage_init": ""
        },
        "script": "addtoany\\.com/menu/page\\.js"
      },
      "Adminer": {
        "cats": [
          3
        ],
        "html": [
          "Adminer</a> <span class=\"version\">([\\d.]+)</span>\\;version:\\1",
          "onclick=\"bodyClick\\(event\\);\" onload=\"verifyVersion\\('([\\d.]+)'\\);\">\\;version:\\1"
        ],
        "implies": "PHP"
      },
      "Adnegah": {
        "cats": [
          36
        ],
        "headers": {
          "X-Advertising-By": "adnegah\\.net"
        },
        "html": "<iframe [^>]*src=\"[^\"]+adnegah\\.net",
        "script": "[^a-z]adnegah.*\\.js$"
      },
      "Adobe ColdFusion": {
        "cats": [
          18
        ],
        "headers": {
          "Cookie": "CFTOKEN="
        },
        "html": "<!-- START headerTags\\.cfm",
        "implies": "CFML",
        "js": {
          "_cfEmails": ""
        },
        "script": "/cfajax/",
        "url": "\\.cfm(?:$|\\?)"
      },
      "Adobe DTM": {
        "cats": [
          42
        ],
        "script": "//assets.adobedtm.com/"
      },
      "Adobe Experience Manager": {
        "cats": [
          1
        ],
        "html": [
          "<div class=\"[^\"]*parbase",
          "<div[^>]+data-component-path=\"[^\"+]jcr:"
        ],
        "implies": "Java",
        "script": "/etc/designs/"
      },
      "Adobe GoLive": {
        "cats": [
          20
        ],
        "meta": {
          "generator": "Adobe GoLive(?:\\s([\\d.]+))?\\;version:\\1"
        }
      },
      "Adobe Muse": {
        "cats": [
          20
        ],
        "meta": {
          "generator": "^Muse(?:$| ?/?(\\d[\\d.]+))\\;version:\\1"
        }
      },
      "Adobe RoboHelp": {
        "cats": [
          4
        ],
        "js": {
          "gbWhLang": "",
          "gbWhMsg": "",
          "gbWhProxy": "",
          "gbWhUtil": "",
          "gbWhVer": ""
        },
        "meta": {
          "generator": "^Adobe RoboHelp(?: ([\\d]+))?\\;version:\\1"
        },
        "script": "(?:wh(?:utils|ver|proxy|lang|topic|msg)|ehlpdhtm)\\.js"
      },
      "ADPLAN": {
        "cats": [
          10
        ],
        "script": [
          "^https?://[^.]+\\.adplan7\\.com/\\;version:7",
          "^https?://(?!o\\.)\\w+\\.advg\\.jp/"
        ]
      },
      "Advanced Web Stats": {
        "cats": [
          10
        ],
        "html": "aws\\.src = [^<]+caphyon-analytics",
        "implies": "Java"
      },
      "Advert Stream": {
        "cats": [
          36
        ],
        "js": {
          "advst_is_above_the_fold": ""
        },
        "script": "(?:ad\\.advertstream\\.com|adxcore\\.com)"
      },
      "Adyen": {
        "cats": [
          41
        ],
        "js": {
          "adyen.encrypt.version": "^(.+)$\\;version:\\1"
        }
      },
      "Adzerk": {
        "cats": [
          36
        ],
        "html": "<iframe [^>]*src=\"[^\"]+adzerk\\.net",
        "js": {
          "ados": "",
          "adosResults": ""
        },
        "script": "adzerk\\.net/ados\\.js"
      },
      "Aegea": {
        "cats": [
          11
        ],
        "headers": {
          "X-Powered-By": "^E2 Aegea v(\\d+)$\\;version:\\1"
        },
        "implies": [
          "PHP",
          "jQuery"
        ]
      },
      "Afosto": {
        "cats": [
          6
        ],
        "headers": {
          "X-Powered-By": "Afosto SaaS BV"
        }
      },
      "AfterBuy": {
        "cats": [
          6
        ],
        "html": [
          "<dd>This OnlineStore is brought to you by ViA-Online GmbH Afterbuy\\. Information and contribution at https://www\\.afterbuy\\.de</dd>"
        ],
        "script": "shop-static\\.afterbuy\\.de"
      },
      "Ahoy": {
        "cats": [
          10
        ],
        "js": {
          "ahoy": ""
        },
        "cookies": {
          "ahoy_track": "",
          "ahoy_visit": "",
          "ahoy_visitor": ""
        }
      },
      "Aircall": {
        "cats": [
          52
        ],
        "script": "^https?://cdn\\.aircall\\.io/"
      },
      "Airee": {
        "cats": [
          31
        ],
        "headers": {
          "Server": "^Airee"
        }
      },
      "Akamai": {
        "cats": [
          31
        ],
        "headers": {
          "X-Akamai-Transformed": ""
        }
      },
      "Akaunting": {
        "cats": [
          55
        ],
        "headers": {
          "X-Akaunting": "^Free Accounting Software$"
        },
        "html": [
          "<link[^>]+akaunting-green\\.css",
          "Powered By Akaunting: <a [^>]*href=\"https?://(?:www\\.)?akaunting\\.com[^>]+>"
        ],
        "implies": "Laravel"
      },
      "Akka HTTP": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "Server": "akka-http(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "Algolia Realtime Search": {
        "cats": [
          29
        ],
        "js": {
          "AlgoliaSearch": "",
          "algoliasearch.version": "^(.+)$\\;version:\\1"
        }
      },
      "All in One SEO Pack": {
        "cats": [
          54
        ],
        "html": "<!-- All in One SEO Pack ([\\d.]+) \\;version:\\1",
        "implies": "WordPress"
      },
      "Allegro RomPager": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Allegro-Software-RomPager(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "AlloyUI": {
        "cats": [
          12
        ],
        "implies": [
          "Bootstrap",
          "YUI"
        ],
        "js": {
          "AUI": ""
        },
        "script": "^https?://cdn\\.alloyui\\.com/"
      },
      "Amaya": {
        "cats": [
          20
        ],
        "meta": {
          "generator": "Amaya(?: V?([\\d.]+[a-z]))?\\;version:\\1"
        }
      },
      "Amazon Cloudfront": {
        "cats": [
          31
        ],
        "headers": {
          "Via": "\\(CloudFront\\)$",
          "X-Amz-Cf-Id": ""
        },
        "implies": "Amazon Web Services"
      },
      "Amazon EC2": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "\\(Amazon\\)"
        },
        "implies": "Amazon Web Services"
      },
      "Amazon Web Services": {
        "cats": [
          62
        ]
      },
      "Amazon ECS": {
        "cats": [
          63
        ],
        "headers": {
          "Server": "^ECS"
        },
        "implies": [
          "Amazon Web Services",
          "Docker"
        ]
      },
      "Amazon ELB": {
        "cats": [
          65
        ],
        "cookies": {
          "AWSELB": ""
        },
        "implies": "Amazon Web Services"
      },
      "Amazon S3": {
        "cats": [
          19
        ],
        "headers": {
          "Server": "^AmazonS3$"
        },
        "implies": "Amazon Web Services"
      },
      "Amber": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "X-Powered-By": "^Amber$"
        }
      },
      "Ametys": {
        "cats": [
          1
        ],
        "implies": "Java",
        "meta": {
          "generator": "(?:Ametys|Anyware Technologies)"
        },
        "script": "ametys\\.js"
      },
      "Amiro.CMS": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "Amiro"
        }
      },
      "Amplitude": {
        "cats": [
          10
        ],
        "script": [
          "cdn\\.amplitude\\.com"
        ]
      },
      "Analysys Ark": {
        "cats": [
          10
        ],
        "js": {
          "AnalysysAgent": ""
        },
        "cookies": {
          "ARK_ID": ""
        },
        "script": "AnalysysFangzhou_JS_SDK\\.min\\.js\\?v=([\\d.]+)\\;version:\\1"
      },
      "Anetwork": {
        "cats": [
          36
        ],
        "script": "static-cdn\\.anetwork\\.ir/"
      },
      "Angular": {
        "cats": [
          12
        ],
        "excludes": [
          "AngularDart",
          "AngularJS"
        ],
        "html": "<[^>]+ ng-version=\"([\\d.]+)\"\\;version:\\1",
        "js": {
          "ng.coreTokens": "",
          "ng.probe": ""
        }
      },
      "Angular Material": {
        "cats": [
          18
        ],
        "implies": "AngularJS",
        "js": {
          "ngMaterial": ""
        },
        "script": "/([\\d.rc-]+)?/angular-material(?:\\.min)?\\.js\\;version:\\1"
      },
      "AngularDart": {
        "cats": [
          18
        ],
        "excludes": [
          "Angular",
          "AngularJS"
        ],
        "implies": "Dart",
        "js": {
          "ngTestabilityRegistries": ""
        }
      },
      "AngularJS": {
        "cats": [
          12
        ],
        "excludes": [
          "Angular",
          "AngularDart"
        ],
        "html": [
          "<(?:div|html)[^>]+ng-app=",
          "<ng-app"
        ],
        "js": {
          "angular": "",
          "angular.version.full": "^(.+)$\\;version:\\1"
        },
        "script": [
          "angular[.-]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "/([\\d.]+(?:-?rc[.\\d]*)*)/angular(?:\\.min)?\\.js\\;version:\\1",
          "angular.*\\.js"
        ]
      },
      "Ant Design": {
        "cats": [
          12
        ],
        "html": [
          "<[^>]*class=\"ant-(?:btn|col|row|layout|breadcrumb|menu|pagination|steps|select|cascader|checkbox|calendar|form|input-number|input|mention|rate|radio|slider|switch|tree-select|time-picker|transfer|upload|avatar|badge|card|carousel|collapse|list|popover|tooltip|table|tabs|tag|timeline|tree|alert|modal|message|notification|progress|popconfirm|spin|anchor|back-top|divider|drawer)",
          "<i class=\"anticon anticon-"
        ],
        "implies": [
          "React"
        ],
        "js": {
          "antd": ""
        }
      },
      "Apache": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "(?:Apache(?:$|/([\\d.]+)|[^/-])|(?:^|\\b)HTTPD)\\;version:\\1"
        }
      },
      "Apache HBase": {
        "cats": [
          34
        ],
        "html": "<style[^>]+static/hbase",
        "implies": "Java"
      },
      "Apache Hadoop": {
        "cats": [
          34
        ],
        "html": "<style[^>]+static/hadoop"
      },
      "Apache JSPWiki": {
        "cats": [
          8
        ],
        "html": "<html[^>]* xmlns:jspwiki=",
        "implies": "Apache Tomcat",
        "script": "jspwiki",
        "url": "wiki\\.jsp"
      },
      "Apache Tomcat": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^Apache-Coyote(?:/([\\d.]+))?\\;version:\\1",
          "X-Powered-By": "\\bTomcat\\b(?:-([\\d.]+))?\\;version:\\1"
        },
        "implies": "Java"
      },
      "Apache Traffic Server": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "ATS/?([\\d.]+)?\\;version:\\1"
        }
      },
      "Apache Wicket": {
        "cats": [
          18
        ],
        "implies": "Java",
        "js": {
          "Wicket": ""
        }
      },
      "ApexPages": {
        "cats": [
          51
        ],
        "headers": {
          "X-Powered-By": "Salesforce\\.com ApexPages"
        },
        "implies": "Salesforce"
      },
      "Apostrophe CMS": {
        "cats": [
          1
        ],
        "html": "<[^>]+data-apos-refreshable[^>]",
        "implies": "Node.js"
      },
      "AppNexus": {
        "cats": [
          36
        ],
        "html": "<(?:iframe|img)[^>]+adnxs\\.(?:net|com)",
        "script": "adnxs\\.(?:net|com)"
      },
      "Appcues": {
        "cats": [
          58
        ],
        "script": "fast\\.appcues.com*\\.js"
      },
      "Arastta": {
        "cats": [
          6
        ],
        "excludes": "OpenCart",
        "headers": {
          "Arastta": "^(.+)$\\;version:\\1",
          "X-Arastta": ""
        },
        "html": "Powered by <a [^>]*href=\"https?://(?:www\\.)?arastta\\.org[^>]+>Arastta",
        "implies": "PHP",
        "script": "arastta\\.js"
      },
      "ArcGIS API for JavaScript": {
        "cats": [
          35
        ],
        "script": [
          "js\\.arcgis\\.com",
          "basemaps\\.arcgis\\.com"
        ]
      },
      "Artifactory": {
        "cats": [
          47
        ],
        "html": [
          "<span class=\"version\">Artifactory(?: Pro)?(?: Power Pack)?(?: ([\\d.]+))?\\;version:\\1"
        ],
        "js": {
          "ArtifactoryUpdates": ""
        },
        "script": [
          "wicket/resource/org\\.artifactory\\."
        ]
      },
      "Artifactory Web Server": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Artifactory(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": [
          "Artifactory"
        ]
      },
      "ArvanCloud": {
        "cats": [
          31
        ],
        "headers": {
          "AR-PoweredBy": "Arvan Cloud \\(arvancloud\\.com\\)"
        },
        "js": {
          "ArvanCloud": ""
        }
      },
      "AsciiDoc": {
        "cats": [
          1,
          20,
          27
        ],
        "js": {
          "asciidoc": ""
        },
        "meta": {
          "generator": "^AsciiDoc ([\\d.]+)\\;version:\\1"
        }
      },
      "Asciinema": {
        "cats": [
          14
        ],
        "html": "<asciinema-player",
        "js": {
          "asciinema": ""
        },
        "script": "asciinema\\.org/"
      },
      "Atlassian Bitbucket": {
        "cats": [
          47
        ],
        "html": "<li>Atlassian Bitbucket <span title=\"[a-z0-9]+\" id=\"product-version\" data-commitid=\"[a-z0-9]+\" data-system-build-number=\"[a-z0-9]+\"> v([\\d.]+)<\\;version:\\1",
        "implies": "Python",
        "js": {
          "bitbucket": ""
        },
        "meta": {
          "application-name": "Bitbucket"
        }
      },
      "Atlassian Confluence": {
        "cats": [
          8
        ],
        "headers": {
          "X-Confluence-Request-Time": ""
        },
        "html": "Powered by <a href=[^>]+atlassian\\.com/software/confluence(?:[^>]+>Atlassian Confluence</a> ([\\d.]+))?\\;version:\\1",
        "implies": "Java",
        "meta": {
          "confluence-request-time": ""
        }
      },
      "Atlassian FishEye": {
        "cats": [
          47
        ],
        "cookies": {
          "FESESSIONID": ""
        },
        "html": "<title>(?:Log in to )?FishEye (?:and Crucible )?([\\d.]+)?</title>\\;version:\\1"
      },
      "Atlassian Jira": {
        "cats": [
          13
        ],
        "html": "Powered by\\s+<a href=[^>]+atlassian\\.com/(?:software/jira|jira-bug-tracking/)[^>]+>Atlassian\\s+JIRA(?:[^v]*v(?:ersion: )?(\\d+\\.\\d+(?:\\.\\d+)?))?\\;version:\\1",
        "implies": "Java",
        "js": {
          "jira": ""
        },
        "meta": {
          "ajs-version-number": "^(.+)$\\;version:\\1",
          "application-name": "JIRA"
        }
      },
      "Atlassian Jira Issue Collector": {
        "cats": [
          13,
          47
        ],
        "script": [
          "jira-issue-collector-plugin",
          "atlassian\\.jira\\.collector\\.plugin"
        ]
      },
      "Aurelia": {
        "cats": [
          12
        ],
        "html": [
          "<[^>]+aurelia-app=[^>]",
          "<[^>]+data-main=[^>]aurelia-bootstrapper",
          "<[^>]+au-target-id=[^>]\\d"
        ],
        "script": [
          "aurelia(?:\\.min)?\\.js"
        ]
      },
      "Avangate": {
        "cats": [
          6
        ],
        "html": "<link[^>]* href=\"^https?://edge\\.avangate\\.net/",
        "js": {
          "__avng8_": "",
          "avng8_": ""
        },
        "script": "^https?://edge\\.avangate\\.net/"
      },
      "Awesomplete": {
        "cats": [
          29
        ],
        "html": "<link[^>]+href=\"[^>]*awesomplete(?:\\.min)?\\.css",
        "js": {
          "awesomplete": ""
        },
        "script": "/awesomplete\\.js(?:$|\\?)"
      },
      "BEM": {
        "cats": [
          12
        ],
        "html": "<[^>]+data-bem"
      },
      "BIGACE": {
        "cats": [
          1
        ],
        "html": "(?:Powered by <a href=\"[^>]+BIGACE|<!--\\s+Site is running BIGACE)",
        "implies": "PHP",
        "meta": {
          "generator": "BIGACE ([\\d.]+)\\;version:\\1"
        }
      },
      "Bablic": {
        "cats": [
          3,
          9
        ],
        "js": {
          "bablic": ""
        }
      },
      "Backbone.js": {
        "cats": [
          12
        ],
        "implies": "Underscore.js",
        "js": {
          "Backbone": "",
          "Backbone.VERSION": "^(.+)$\\;version:\\1"
        },
        "script": "backbone.*\\.js"
      },
      "Backdrop": {
        "cats": [
          1
        ],
        "excludes": "Drupal",
        "implies": "PHP",
        "js": {
          "Backdrop": ""
        },
        "meta": {
          "generator": "Backdrop CMS(?: (\\d))?\\;version:\\1"
        }
      },
      "Backtory": {
        "cats": [
          31
        ],
        "headers": {
          "X-Powered-By": "Backtory"
        }
      },
      "Banshee": {
        "cats": [
          1,
          18
        ],
        "html": "Built upon the <a href=\"[^>]+banshee-php\\.org/\">[a-z]+</a>(?:v([\\d.]+))?\\;version:\\1",
        "implies": "PHP",
        "meta": {
          "generator": "Banshee PHP"
        }
      },
      "BaseHTTP": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "BaseHTTP\\/?([\\d\\.]+)?\\;version:\\1"
        },
        "implies": "Python"
      },
      "BigBangShop": {
        "cats": [
          6
        ],
        "headers": {
          "X-SERVER": "BIGBANGSHOP"
        }
      },
      "BigDump": {
        "cats": [
          3
        ],
        "html": "<!-- <h1>BigDump: Staggered MySQL Dump Importer ver\\. ([\\d.b]+)\\;version:\\1",
        "implies": [
          "MySQL",
          "PHP"
        ]
      },
      "Bigcommerce": {
        "cats": [
          6
        ],
        "html": "<link href=[^>]+cdn\\d+\\.bigcommerce\\.com/",
        "script": "cdn\\d+\\.bigcommerce\\.com/",
        "url": "mybigcommerce\\.com"
      },
      "Bigware": {
        "cats": [
          6
        ],
        "cookies": {
          "bigWAdminID": "",
          "bigwareCsid": ""
        },
        "html": "(?:Diese <a href=[^>]+bigware\\.de|<a href=[^>]+/main_bigware_\\d+\\.php)",
        "implies": "PHP",
        "url": "(?:\\?|&)bigWAdminID="
      },
      "BittAds": {
        "cats": [
          36
        ],
        "js": {
          "bitt": ""
        },
        "script": "bittads\\.com/js/bitt\\.js$"
      },
      "Bizweb": {
        "cats": [
          6
        ],
        "js": {
          "Bizweb": ""
        }
      },
      "Blade": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "X-Powered-By": "blade-([\\w.]+)?\\;version:\\1"
        },
        "implies": "Java"
      },
      "Blesta": {
        "cats": [
          6
        ],
        "cookies": {
          "blesta_sid": ""
        }
      },
      "Blip.tv": {
        "cats": [
          14
        ],
        "html": "<(?:param|embed|iframe)[^>]+blip\\.tv/play"
      },
      "Blogger": {
        "cats": [
          11
        ],
        "implies": "Python",
        "meta": {
          "generator": "^Blogger$"
        },
        "url": "^https?://[^/]+\\.blogspot\\.com"
      },
      "Bluefish": {
        "cats": [
          20
        ],
        "meta": {
          "generator": "Bluefish(?:\\s([\\d.]+))?\\;version:\\1"
        }
      },
      "Boa": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Boa\\/?([\\d\\.a-z]+)?\\;version:\\1"
        }
      },
      "Boba.js": {
        "cats": [
          59
        ],
        "implies": "Google Analytics",
        "script": "boba(?:\\.min)?\\.js"
      },
      "Bold Chat": {
        "cats": [
          52
        ],
        "script": "^https?://vmss\\.boldchat\\.com/aid/\\d{18}/bc\\.vms4/vms\\.js"
      },
      "BoldGrid": {
        "cats": [
          1,
          11
        ],
        "html": [
          "<link rel=[\"']stylesheet[\"'] [^>]+boldgrid",
          "<link rel=[\"']stylesheet[\"'] [^>]+post-and-page-builder",
          "<link[^>]+s\\d+\\.boldgrid\\.com"
        ],
        "script": "/wp-content/plugins/post-and-page-builder",
        "implies": "WordPress"
      },
      "Bolt": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "Bolt"
        }
      },
      "Bonfire": {
        "cats": [
          18
        ],
        "cookies": {
          "bf_session": ""
        },
        "html": "Powered by <a[^>]+href=\"https?://(?:www\\.)?cibonfire\\.com[^>]*>Bonfire v([^<]+)\\;version:\\1",
        "implies": "CodeIgniter"
      },
      "Bootstrap": {
        "cats": [
          18
        ],
        "html": [
          "<style>/\\*!\\* Bootstrap v(\\d\\.\\d\\.\\d)\\;version:\\1",
          "<link[^>]+?href=[^\"]/css/([\\d.]+)/bootstrap\\.(?:min\\.)?css\\;version:\\1",
          "<link[^>]+?href=\"[^\"]*bootstrap(?:\\.min)?\\.css",
          "<div[^>]+class=\"[^\"]*glyphicon glyphicon-"
        ],
        "js": {
          "bootstrap.Alert.VERSION": "^(.+)$\\;version:\\1",
          "jQuery.fn.tooltip.Constructor.VERSION": "^(.+)$\\;version:\\1"
        },
        "script": [
          "twitter\\.github\\.com/bootstrap",
          "bootstrap[.-]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "(?:/([\\d.]+))?(?:/js)?/bootstrap(?:\\.min)?\\.js\\;version:\\1"
        ]
      },
      "Bootstrap Table": {
        "cats": [
          59
        ],
        "html": "<link[^>]+href=\"[^>]*bootstrap-table(?:\\.min)?\\.css",
        "implies": [
          "Bootstrap",
          "jQuery"
        ],
        "script": "bootstrap-table(?:\\.min)?\\.js"
      },
      "Bounce Exchange": {
        "cats": [
          32
        ],
        "script": "^https?://tag\\.bounceexchange\\.com/",
        "js": {
          "bouncex": ""
        }
      },
      "Braintree": {
        "cats": [
          41
        ],
        "js": {
          "Braintree": "",
          "Braintree.version": "^(.+)$\\;version:\\1"
        }
      },
      "Brightspot": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "^Brightspot$"
        },
        "implies": "Java"
      },
      "BrowserCMS": {
        "cats": [
          1
        ],
        "implies": "Ruby",
        "meta": {
          "generator": "BrowserCMS ([\\d.]+)\\;version:\\1"
        }
      },
      "Bubble": {
        "cats": [
          1,
          3,
          18,
          22
        ],
        "implies": "Node.js",
        "js": {
          "appquery": ""
        }
      },
      "BugSnag": {
        "cats": [
          10
        ],
        "js": {
          "Bugsnag": "",
          "bugsnag": "",
          "bugsnagClient": ""
        },
        "script": "/bugsnag.*\\.js"
      },
      "Bugzilla": {
        "cats": [
          13
        ],
        "html": [
          "href=\"enter_bug\\.cgi\">",
          "<main id=\"bugzilla-body\"",
          "<a href=\"https?://www\\.bugzilla\\.org/docs/([0-9.]+)/[^>]+>Help<\\;version:\\1",
          "<span id=\"information\" class=\"header_addl_info\">version ([\\d.]+)<\\;version:\\1"
        ],
        "cookies": {
          "Bugzilla_login_request_cookie": ""
        },
        "implies": "Perl",
        "js": {
          "BUGZILLA": ""
        },
        "meta": {
          "generator": "Bugzilla ?([\\d.]+)?\\;version:\\1"
        }
      },
      "Bulma": {
        "cats": [
          18
        ],
        "html": "<link[^>]+?href=\"[^\"]+bulma(?:\\.min)?\\.css"
      },
      "Burning Board": {
        "cats": [
          2
        ],
        "html": "<a href=\"[^>]+woltlab\\.com[^<]+<strong>Burning Board",
        "implies": [
          "PHP",
          "Woltlab Community Framework"
        ]
      },
      "Business Catalyst": {
        "cats": [
          1
        ],
        "html": "<!-- BC_OBNW -->",
        "script": "CatalystScripts"
      },
      "BuySellAds": {
        "cats": [
          36
        ],
        "script": "^https?://s\\d\\.buysellads\\.com/",
        "js": {
          "_bsa": "",
          "_bsaPRO": "",
          "_bsap": "",
          "_bsap_serving_callback": ""
        }
      },
      "CDN77": {
        "cats": [
          31
        ],
        "headers": {
          "Server": "^CDN77-Turbo$"
        }
      },
      "CFML": {
        "cats": [
          27
        ]
      },
      "CKEditor": {
        "cats": [
          24
        ],
        "js": {
          "CKEDITOR": "",
          "CKEDITOR.version": "^(.+)$\\;version:\\1",
          "CKEDITOR_BASEPATH": ""
        }
      },
      "CMS Made Simple": {
        "cats": [
          1
        ],
        "cookies": {
          "CMSSESSID": ""
        },
        "implies": "PHP",
        "meta": {
          "generator": "CMS Made Simple"
        }
      },
      "CMSimple": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "CMSimple( [\\d.]+)?\\;version:\\1"
        }
      },
      "CPG Dragonfly": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "^Dragonfly CMS"
        },
        "implies": "PHP",
        "meta": {
          "generator": "CPG Dragonfly"
        }
      },
      "CS Cart": {
        "cats": [
          6
        ],
        "html": [
          "&nbsp;Powered by (?:<a href=[^>]+cs-cart\\.com|CS-Cart)",
          "\\.cm-noscript[^>]+</style>"
        ],
        "implies": "PHP",
        "js": {
          "fn_compare_strings": ""
        }
      },
      "CacheFly": {
        "cats": [
          31
        ],
        "headers": {
          "Server": "^CFS ",
          "X-CF1": "",
          "X-CF2": ""
        }
      },
      "Caddy": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^Caddy$"
        },
        "implies": "Go"
      },
      "CakePHP": {
        "cats": [
          18
        ],
        "cookies": {
          "cakephp": ""
        },
        "implies": "PHP",
        "meta": {
          "application-name": "CakePHP"
        }
      },
      "Captch Me": {
        "cats": [
          16,
          36
        ],
        "js": {
          "Captchme": ""
        },
        "script": "^https?://api\\.captchme\\.net/"
      },
      "Carbon Ads": {
        "cats": [
          36
        ],
        "html": "<[a-z]+ [^>]*id=\"carbonads-container\"",
        "js": {
          "_carbonads": ""
        },
        "script": "//(?:engine|srv)\\.carbonads\\.com\\/"
      },
      "Cargo": {
        "cats": [
          1
        ],
        "html": "<link [^>]+Cargo feed",
        "implies": "PHP",
        "meta": {
          "cargo_title": ""
        },
        "script": "/cargo\\."
      },
      "Catberry.js": {
        "cats": [
          12,
          18
        ],
        "headers": {
          "X-Powered-By": "Catberry"
        },
        "implies": "Node.js",
        "js": {
          "catberry": "",
          "catberry.version": "^(.+)$\\;version:\\1"
        }
      },
      "CentOS": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "CentOS",
          "X-Powered-By": "CentOS"
        }
      },
      "Chameleon": {
        "cats": [
          1
        ],
        "implies": [
          "Apache",
          "PHP"
        ],
        "meta": {
          "generator": "chameleon-cms"
        }
      },
      "Chamilo": {
        "cats": [
          21
        ],
        "headers": {
          "X-Powered-By": "Chamilo ([\\d.]+)\\;version:\\1"
        },
        "html": "\">Chamilo ([\\d.]+)</a>\\;version:\\1",
        "implies": "PHP",
        "meta": {
          "generator": "Chamilo ([\\d.]+)\\;version:\\1"
        }
      },
      "Chart.js": {
        "cats": [
          25
        ],
        "js": {
          "Chart": "\\;confidence:50",
          "Chart.defaults.doughnut": "",
          "chart.ctx.bezierCurveTo": ""
        },
        "script": [
          "/Chart(?:\\.bundle)?(?:\\.min)?\\.js\\;confidence:75",
          "chartjs\\.org/dist/([\\d.]+(?:-[^/]+)?|master|latest)/Chart.*\\.js\\;version:\\1",
          "cdnjs\\.cloudflare\\.com/ajax/libs/Chart\\.js/([\\d.]+(?:-[^/]+)?)/Chart.*\\.js\\;version:\\1",
          "cdn\\.jsdelivr\\.net/(?:npm|gh/chartjs)/chart\\.js@([\\d.]+(?:-[^/]+)?|latest)/dist/Chart.*\\.js\\;version:\\1"
        ]
      },
      "Chartbeat": {
        "cats": [
          10
        ],
        "js": {
          "_sf_async_config": "",
          "_sf_endpt": ""
        },
        "script": "chartbeat\\.js"
      },
      "Cherokee": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^Cherokee(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "CherryPy": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "Server": "CherryPy\\/?([\\d\\.]+)?\\;version:\\1"
        },
        "implies": "Python"
      },
      "Chevereto": {
        "cats": [
          7
        ],
        "meta": {
          "generator": "^Chevereto ?([0-9.]+)?$\\;version:\\1"
        },
        "script": "/chevereto\\.js",
        "html": "Powered by <a href=\"https?://chevereto\\.com\">",
        "implies": "PHP"
      },
      "Chitika": {
        "cats": [
          36
        ],
        "js": {
          "ch_client": "",
          "ch_color_site_link": ""
        },
        "script": "scripts\\.chitika\\.net/"
      },
      "Ckan": {
        "cats": [
          1
        ],
        "headers": {
          "Access-Control-Allow-Headers": "X-CKAN-API-KEY",
          "Link": "<http://ckan\\.org/>; rel=shortlink"
        },
        "implies": [
          "Python",
          "Solr",
          "Java",
          "PostgreSQL"
        ],
        "meta": {
          "generator": "^ckan ?([0-9.]+)$\\;version:\\1"
        }
      },
      "Clarity": {
        "cats": [
          18
        ],
        "html": [
          "<clr-main-container",
          "<link [^>]*href=\"[^\"]*clr-ui(?:\\.min)?\\.css"
        ],
        "js": {
          "ClarityIcons": ""
        },
        "script": "clr-angular(?:\\.umd)?(?:\\.min)?\\.js",
        "implies": [
          "Angular"
        ]
      },
      "ClickHeat": {
        "cats": [
          10
        ],
        "implies": "PHP",
        "js": {
          "clickHeatServer": ""
        },
        "script": "clickheat.*\\.js"
      },
      "ClickTale": {
        "cats": [
          10
        ],
        "js": {
          "clickTaleStartEventSignal": ""
        }
      },
      "Clicky": {
        "cats": [
          10
        ],
        "js": {
          "clicky": ""
        },
        "script": "static\\.getclicky\\.com"
      },
      "Clientexec": {
        "cats": [
          6
        ],
        "html": "clientexec\\.[^>]*\\s?=\\s?[^>]*;"
      },
      "Clipboard.js": {
        "cats": [
          19
        ],
        "script": "clipboard(?:-([\\d.]+))?(?:\\.min)?\\.js\\;version:\\1"
      },
      "CloudCart": {
        "cats": [
          6
        ],
        "meta": {
          "author": "^CloudCart LLC$"
        },
        "script": "/cloudcart-(?:assets|storage)/"
      },
      "CloudFlare": {
        "cats": [
          31
        ],
        "headers": {
          "Server": "^cloudflare$",
          "cf-cache-status": "",
          "cf-ray": ""
        },
        "cookies": {
          "__cfduid": ""
        },
        "js": {
          "CloudFlare": ""
        }
      },
      "Cloudcoins": {
        "cats": [
          56
        ],
        "js": {
          "CLOUDCOINS": ""
        },
        "script": "https?://cdn\\.cloudcoins\\.co/javascript/cloudcoins\\.min\\.js"
      },
      "Cloudera": {
        "cats": [
          34
        ],
        "headers": {
          "Server": "cloudera"
        }
      },
      "Coaster CMS": {
        "cats": [
          1
        ],
        "implies": "Laravel",
        "meta": {
          "generator": "^Coaster CMS v([\\d.]+)$\\;version:\\1"
        }
      },
      "CodeIgniter": {
        "cats": [
          18
        ],
        "cookies": {
          "ci_csrf_token": "^(.+)$\\;version:\\1?2+:",
          "ci_session": "",
          "exp_last_activity": "",
          "exp_tracker": ""
        },
        "html": "<input[^>]+name=\"ci_csrf_token\"\\;version:2+",
        "implies": "PHP"
      },
      "CodeMirror": {
        "cats": [
          19
        ],
        "js": {
          "CodeMirror": "",
          "CodeMirror.version": "^(.+)$\\;version:\\1"
        }
      },
      "CoinHive": {
        "cats": [
          56
        ],
        "js": {
          "CoinHive": ""
        },
        "script": [
          "\\/(?:coinhive|(authedmine))(?:\\.min)?\\.js\\;version:\\1?opt-in:",
          "coinhive\\.com/lib"
        ],
        "url": "https?://cnhv\\.co/"
      },
      "CoinHive Captcha": {
        "cats": [
          16,
          56
        ],
        "html": "(?:<div[^>]+class=\"coinhive-captcha[^>]+data-key|<div[^>]+data-key[^>]+class=\"coinhive-captcha)",
        "script": "https?://authedmine\\.com/(?:lib/captcha|captcha)"
      },
      "Coinhave": {
        "cats": [
          56
        ],
        "script": "https?://coin-have\\.com/c/[0-9a-zA-Z]{4}\\.js"
      },
      "Coinimp": {
        "cats": [
          56
        ],
        "js": {
          "Client.Anonymous": "\\;confidence:50"
        },
        "script": "https?://www\\.hashing\\.win/scripts/min\\.js"
      },
      "Coinlab": {
        "cats": [
          56
        ],
        "js": {
          "Coinlab": ""
        },
        "script": "https?://coinlab\\.biz/lib/coinlab\\.js\\?id="
      },
      "ColorMeShop": {
        "cats": [
          6
        ],
        "js": {
          "Colorme": ""
        }
      },
      "Comandia": {
        "cats": [
          6
        ],
        "html": "<link[^>]+=['\"]//cdn\\.mycomandia\\.com",
        "js": {
          "Comandia": ""
        }
      },
      "Combeenation": {
        "cats": [
          6
        ],
        "html": "<iframe[^>]+src=\"[^>]+portal\\.combeenation\\.com"
      },
      "Commerce Server": {
        "cats": [
          6
        ],
        "headers": {
          "COMMERCE-SERVER-SOFTWARE": ""
        },
        "implies": "Microsoft ASP.NET"
      },
      "CompaqHTTPServer": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "CompaqHTTPServer\\/?([\\d\\.]+)?\\;version:\\1"
        }
      },
      "Concrete5": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "js": {
          "CCM_IMAGE_PATH": ""
        },
        "cookies": {
          "CONCRETE5": ""
        },
        "meta": {
          "generator": "^concrete5 - ([\\d.]+)$\\;version:\\1"
        },
        "script": "/concrete/js/"
      },
      "Connect": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "^Connect$"
        },
        "implies": "Node.js"
      },
      "Contao": {
        "cats": [
          1
        ],
        "html": [
          "<!--[^>]+powered by (?:TYPOlight|Contao)[^>]*-->",
          "<link[^>]+(?:typolight|contao)\\.css"
        ],
        "implies": "PHP",
        "meta": {
          "generator": "^Contao Open Source CMS$"
        }
      },
      "Contenido": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "Contenido ([\\d.]+)\\;version:\\1"
        }
      },
      "Contensis": {
        "cats": [
          1
        ],
        "implies": [
          "Java",
          "CFML"
        ],
        "meta": {
          "generator": "Contensis CMS Version ([\\d.]+)\\;version:\\1"
        }
      },
      "ContentBox": {
        "cats": [
          1,
          11
        ],
        "implies": "Adobe ColdFusion",
        "meta": {
          "generator": "ContentBox powered by ColdBox"
        }
      },
      "Contentful": {
        "cats": [
          1
        ],
        "html": "<[^>]+(?:https?:)?//(?:assets|downloads|images|videos)\\.(?:ct?fassets\\.net|contentful\\.com)"
      },
      "ConversionLab": {
        "cats": [
          10
        ],
        "script": "conversionlab\\.trackset\\.com/track/tsend\\.js"
      },
      "Coppermine": {
        "cats": [
          7
        ],
        "html": "<!--Coppermine Photo Gallery ([\\d.]+)\\;version:\\1",
        "implies": "PHP"
      },
      "Cosmoshop": {
        "cats": [
          6
        ],
        "script": "cosmoshop_functions\\.js"
      },
      "Cotonti": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "Cotonti"
        }
      },
      "CouchDB": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "CouchDB/([\\d.]+)\\;version:\\1"
        }
      },
      "Countly": {
        "cats": [
          10
        ],
        "js": {
          "Countly": ""
        }
      },
      "Cowboy": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "Server": "^Cowboy$"
        },
        "implies": "Erlang"
      },
      "CppCMS": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "^CppCMS/([\\d.]+)$\\;version:\\1"
        },
        "implies": "C\\+\\+"
      },
      "Craft CMS": {
        "cats": [
          1
        ],
        "cookies": {
          "CraftSessionId": ""
        },
        "headers": {
          "X-Powered-By": "\\bCraft CMS\\b"
        },
        "implies": "Yii"
      },
      "Craft Commerce": {
        "cats": [
          6
        ],
        "headers": {
          "X-Powered-By": "\\bCraft Commerce\\b"
        },
        "implies": "Craft CMS"
      },
      "Crazy Egg": {
        "cats": [
          10
        ],
        "js": {
          "CE2": ""
        },
        "script": "script\\.crazyegg\\.com/pages/scripts/\\d+/\\d+\\.js"
      },
      "Criteo": {
        "cats": [
          36
        ],
        "js": {
          "Criteo": "",
          "criteo_pubtag": "",
          "criteo_q": ""
        },
        "script": [
          "//(?:cas\\.criteo\\.com|(?:[^/]\\.)?criteo\\.net)/",
          "//static.criteo.net/js/ld/ld.js"
        ]
      },
      "Cross Pixel": {
        "cats": [
          10
        ],
        "js": {
          "cp_C4w1ldN2d9PmVrkN": ""
        },
        "script": "tag\\.crsspxl\\.com/s1\\.js"
      },
      "Crypto-Loot": {
        "cats": [
          56
        ],
        "js": {
          "CRLT.CONFIG.ASMJS_NAME": "",
          "CryptoLoot": ""
        },
        "script": [
          "^/crypto-loot\\.com/lib/",
          "^/webmine\\.pro/",
          "^/cryptoloot\\.pro/",
          "/crlt\\.js\\;confidence:75"
        ]
      },
      "CubeCart": {
        "cats": [
          6
        ],
        "html": "(?:Powered by <a href=[^>]+cubecart\\.com|<p[^>]+>Powered by CubeCart)",
        "implies": "PHP",
        "meta": {
          "generator": "cubecart"
        }
      },
      "Cufon": {
        "cats": [
          17
        ],
        "js": {
          "Cufon": ""
        },
        "script": "cufon-yui\\.js"
      },
      "D3": {
        "cats": [
          25
        ],
        "js": {
          "d3.version": "^(.+)$\\;version:\\1"
        },
        "script": "/d3(?:\\. v\\d+)?(?:\\.min)?\\.js"
      },
      "DHTMLX": {
        "cats": [
          59
        ],
        "script": "dhtmlxcommon\\.js"
      },
      "DM Polopoly": {
        "cats": [
          1
        ],
        "html": "<(?:link [^>]*href|img [^>]*src)=\"/polopoly_fs/",
        "implies": "Java"
      },
      "DNN": {
        "cats": [
          1
        ],
        "cookies": {
          "DotNetNukeAnonymous": ""
        },
        "headers": {
          "Cookie": "dnn_IsMobile=",
          "DNNOutputCache": "",
          "X-Compressed-By": "DotNetNuke"
        },
        "html": [
          "<!-- by DotNetNuke Corporation",
          "<!-- DNN Platform"
        ],
        "implies": "Microsoft ASP.NET",
        "js": {
          "DotNetNuke": "",
          "dnn.apiversion": "^(.+)$\\;version:\\1"
        },
        "meta": {
          "generator": "DotNetNuke"
        },
        "script": [
          "/js/dnncore\\.js",
          "/js/dnn\\.js"
        ]
      },
      "DTG": {
        "cats": [
          1
        ],
        "html": [
          "<a[^>]+Site Powered by DTG"
        ],
        "implies": "Mono.net"
      },
      "Dancer": {
        "cats": [
          18
        ],
        "headers": {
          "Server": "Perl Dancer ([\\d.]+)\\;version:\\1",
          "X-Powered-By": "Perl Dancer ([\\d.]+)\\;version:\\1"
        },
        "implies": "Perl"
      },
      "Danneo CMS": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "CMS Danneo ([\\d.]+)\\;version:\\1"
        },
        "implies": [
          "Apache",
          "PHP"
        ],
        "meta": {
          "generator": "Danneo CMS ([\\d.]+)\\;version:\\1"
        }
      },
      "Dart": {
        "cats": [
          27
        ],
        "excludes": [
          "Angular",
          "AngularJS"
        ],
        "html": "/(?:<script)[^>]+(?:type=\"application/dart\")/",
        "implies": "AngularDart",
        "js": {
          "___dart__$dart_dartObject_ZxYxX_0_": "",
          "___dart_dispatch_record_ZxYxX_0_": ""
        },
        "script": [
          "/(?:\\.)?(?:dart)(?:\\.js)?/",
          "packages/browser/dart\\.js"
        ]
      },
      "Darwin": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "Darwin",
          "X-Powered-By": "Darwin"
        }
      },
      "Datadome": {
        "cats": [
          19
        ],
        "cookies": {
          "datadome": ""
        },
        "script": "^https://ct\\.datadome\\.co/[a-z]\\.js$",
        "headers": {
          "X-DataDome": "",
          "Server": "^DataDome$",
          "X-DataDome-CID": ""
        }
      },
      "DataLife Engine": {
        "cats": [
          1
        ],
        "implies": [
          "PHP",
          "Apache"
        ],
        "js": {
          "dle_root": ""
        },
        "meta": {
          "generator": "DataLife Engine"
        }
      },
      "DataTables": {
        "cats": [
          59
        ],
        "implies": "jQuery",
        "script": "dataTables.*\\.js"
      },
      "Day.js": {
        "cats": [
          59
        ],
        "js": {
          "dayjs": ""
        }
      },
      "Debian": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "Debian",
          "X-Powered-By": "(?:Debian|dotdeb|(potato|woody|sarge|etch|lenny|squeeze|wheezy|jessie|stretch|buster|sid))\\;version:\\1"
        }
      },
      "DedeCMS": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "js": {
          "DedeContainer": ""
        },
        "script": "dedeajax"
      },
      "DirectAdmin": {
        "cats": [
          9
        ],
        "headers": {
          "Server": "DirectAdmin Daemon v([\\d.]+)\\;version:\\1"
        },
        "html": "<a[^>]+>DirectAdmin</a> Web Control Panel",
        "implies": [
          "PHP",
          "Apache"
        ]
      },
      "Discourse": {
        "cats": [
          2
        ],
        "implies": "Ruby on Rails",
        "js": {
          "Discourse": ""
        },
        "meta": {
          "generator": "Discourse(?: ?/?([\\d.]+\\d))?\\;version:\\1"
        }
      },
      "Discuz! X": {
        "cats": [
          2
        ],
        "implies": "PHP",
        "js": {
          "DISCUZCODE": "",
          "discuzVersion": "^(.+)$\\;version:\\1",
          "discuz_uid": ""
        },
        "meta": {
          "generator": "Discuz! X([\\d\\.]+)?\\;version:\\1"
        }
      },
      "Disqus": {
        "cats": [
          15
        ],
        "html": "<div[^>]+id=\"disqus_thread\"",
        "js": {
          "DISQUS": "",
          "disqus_shortname": "",
          "disqus_url": ""
        },
        "script": "disqus_url"
      },
      "Django": {
        "cats": [
          18
        ],
        "html": "(?:powered by <a[^>]+>Django ?([\\d.]+)?<\\/a>|<input[^>]*name=[\"']csrfmiddlewaretoken[\"'][^>]*>)\\;version:\\1",
        "implies": "Python",
        "js": {
          "__admin_media_prefix__": "",
          "django": ""
        }
      },
      "Django CMS": {
        "cats": [
          1
        ],
        "implies": "Django"
      },
      "Docusaurus": {
        "cats": [
          4
        ],
        "implies": [
          "React",
          "webpack"
        ],
        "js": {
          "search.indexName": ""
        },
        "meta": {
          "generator": "^Docusaurus$"
        }
      },
      "Docker": {
        "cats": [
          60
        ],
        "implies": "Linux",
        "html": "<!-- This comment is expected by the docker HEALTHCHECK  -->"
      },
      "Dojo": {
        "cats": [
          59
        ],
        "js": {
          "dojo": "",
          "dojo.version.major": "^(.+)$\\;version:\\1"
        },
        "script": "([\\d.]+)/dojo/dojo(?:\\.xd)?\\.js\\;version:\\1"
      },
      "Dokeos": {
        "cats": [
          21
        ],
        "headers": {
          "X-Powered-By": "Dokeos"
        },
        "html": "(?:Portal <a[^>]+>Dokeos|@import \"[^\"]+dokeos_blue)",
        "implies": [
          "PHP",
          "Xajax",
          "jQuery",
          "CKEditor"
        ],
        "meta": {
          "generator": "Dokeos"
        }
      },
      "DokuWiki": {
        "cats": [
          8
        ],
        "cookies": {
          "DokuWiki": ""
        },
        "html": [
          "<div[^>]+id=\"dokuwiki__>",
          "<a[^>]+href=\"#dokuwiki__"
        ],
        "implies": "PHP",
        "meta": {
          "generator": "^DokuWiki( Release [\\d-]+)?\\;version:\\1"
        }
      },
      "Dotclear": {
        "cats": [
          1
        ],
        "headers": {
          "X-Dotclear-Static-Cache": ""
        },
        "implies": "PHP"
      },
      "DoubleClick Ad Exchange (AdX)": {
        "cats": [
          36
        ],
        "script": [
          "googlesyndication\\.com/pagead/show_ads\\.js",
          "tpc\\.googlesyndication\\.com/safeframe",
          "googlesyndication\\.com.*abg\\.js"
        ]
      },
      "DoubleClick Campaign Manager (DCM)": {
        "cats": [
          36
        ],
        "script": "2mdn\\.net"
      },
      "DoubleClick Floodlight": {
        "cats": [
          36
        ],
        "script": "https?://fls\\.doubleclick\\.net"
      },
      "DoubleClick for Publishers (DFP)": {
        "cats": [
          36
        ],
        "script": "googletagservices\\.com/tag/js/gpt(?:_mobile)?\\.js"
      },
      "DovetailWRP": {
        "cats": [
          1
        ],
        "html": "<link[^>]* href=\"\\/DovetailWRP\\/",
        "implies": "Microsoft ASP.NET",
        "script": "\\/DovetailWRP\\/"
      },
      "Doxygen": {
        "cats": [
          4
        ],
        "html": "(?:<!-- Generated by Doxygen ([\\d.]+)|<link[^>]+doxygen\\.css)\\;version:\\1",
        "meta": {
          "generator": "Doxygen ([\\d.]+)\\;version:\\1"
        }
      },
      "DreamWeaver": {
        "cats": [
          20
        ],
        "html": "<!--[^>]*(?:InstanceBeginEditable|Dreamweaver([^>]+)target|DWLayoutDefaultTable)\\;version:\\1",
        "js": {
          "MM_showMenu": "",
          "MM_preloadImages": "",
          "MM_showHideLayers": ""
        }
      },
      "Drupal": {
        "cats": [
          1
        ],
        "headers": {
          "Expires": "19 Nov 1978",
          "X-Drupal-Cache": "",
          "X-Generator": "^Drupal(?:\\s([\\d.]+))?\\;version:\\1"
        },
        "html": "<(?:link|style)[^>]+\"/sites/(?:default|all)/(?:themes|modules)/",
        "implies": "PHP",
        "js": {
          "Drupal": ""
        },
        "meta": {
          "generator": "^Drupal(?:\\s([\\d.]+))?\\;version:\\1"
        },
        "script": "drupal\\.js"
      },
      "Drupal Commerce": {
        "cats": [
          6
        ],
        "html": "<[^>]+(?:id=\"block[_-]commerce[_-]cart[_-]cart|class=\"commerce[_-]product[_-]field)",
        "implies": "Drupal"
      },
      "Dynamicweb": {
        "cats": [
          1,
          6,
          10
        ],
        "cookies": {
          "Dynamicweb": ""
        },
        "implies": "Microsoft ASP.NET",
        "meta": {
          "generator": "Dynamicweb ([\\d.]+)\\;version:\\1"
        }
      },
      "Dynatrace": {
        "cats": [
          10
        ],
        "headers": {
          "X-dynaTrace-JS-Agent": ""
        },
        "script": "dtagent.*\\.js"
      },
      "EasyEngine": {
        "cats": [
          47,
          9
        ],
        "implies": [
          "Docker"
        ],
        "headers": {
          "x-powered-by": "^EasyEngine (.*)$\\;version:\\1"
        }
      },
      "EC-CUBE": {
        "cats": [
          6
        ],
        "implies": "PHP",
        "script": [
          "eccube\\.js",
          "win_op\\.js"
        ]
      },
      "Elementor": {
        "cats": [
          51
        ],
        "html": [
          "<div class=(?:\"|')[^\"']*elementor",
          "<section class=(?:\"|')[^\"']*elementor",
          "<link [^>]*href=(?:\"|')[^\"']*elementor/assets",
          "<link [^>]*href=(?:\"|')[^\"']*uploads/elementor/css"
        ],
        "js": {
          "elementorFrontend.getElements": ""
        },
        "script": "elementor/assets/js/[^/]+\\.js\\?ver=([\\d.]+)$\\;version:\\1",
        "implies": "WordPress"
      },
      "ELOG": {
        "cats": [
          19
        ],
        "html": "<title>ELOG Logbook Selection</title>"
      },
      "ELOG HTTP": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "ELOG HTTP ?([\\d.-]+)?\\;version:\\1"
        },
        "implies": "ELOG"
      },
      "EPages": {
        "cats": [
          6
        ],
        "headers": {
          "X-Powered-By": "epages 6"
        },
        "html": "<div class=\"BoxContainer\">"
      },
      "EPiServer": {
        "cats": [
          1
        ],
        "cookies": {
          "EPiServer": "",
          "EPiTrace": ""
        },
        "implies": "Microsoft ASP.NET",
        "meta": {
          "generator": "EPiServer"
        }
      },
      "EPrints": {
        "cats": [
          19
        ],
        "implies": "Perl",
        "js": {
          "EPJS_menu_template": "",
          "EPrints": ""
        },
        "meta": {
          "generator": "EPrints ([\\d.]+)\\;version:\\1"
        }
      },
      "EdgeCast": {
        "cats": [
          31
        ],
        "headers": {
          "Server": "^ECD\\s\\(\\S+\\)"
        },
        "url": "https?://(?:[^/]+\\.)?edgecastcdn\\.net/"
      },
      "Elcodi": {
        "cats": [
          6
        ],
        "headers": {
          "X-Elcodi": ""
        },
        "implies": [
          "PHP",
          "Symfony"
        ]
      },
      "Eleanor CMS": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "Eleanor"
        }
      },
      "Element UI": {
        "cats": [
          12
        ],
        "implies": [
          "Vue"
        ],
        "html": [
          "<(?:div|button) class=\"el-(?:table-column|table-filter|popper|pagination|pager|select-group|form|form-item|color-predefine|color-hue-slider|color-svpanel|color-alpha-slider|color-dropdown|color-picker|badge|tree|tree-node|select|message|dialog|checkbox|checkbox-button|checkbox-group|container|steps|carousel|menu|menu-item|submenu|menu-item-group|button|button-group|card|table|select-dropdown|row|tabs|notification|radio|progress|progress-bar|tag|popover|tooltip|cascader|cascader-menus|cascader-menu|time-spinner|spinner|spinner-inner|transfer|transfer-panel|rate|slider|dropdown|dropdown-menu|textarea|input|input-group|popup-parent|radio-group|main|breadcrumb|time-range-picker|date-range-picker|year-table|date-editor|range-editor|time-spinner|date-picker|time-panel|date-table|month-table|picker-panel|collapse|collapse-item|alert|select-dropdown|select-dropdown__empty|select-dropdown__wrap|select-dropdown__list|scrollbar|switch|carousel|upload|upload-dragger|upload-list|upload-cover|aside|input-number|header|message-box|footer|radio-button|step|autocomplete|autocomplete-suggestion|loading-parent|loading-mask|loading-spinner|)"
        ]
      },
      "Eloqua": {
        "cats": [
          32
        ],
        "js": {
          "elqCurESite": "",
          "elqLoad": "",
          "elqSiteID": "",
          "elq_global": ""
        },
        "script": "elqCfg\\.js"
      },
      "EmbedThis Appweb": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Mbedthis-Appweb(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "Ember.js": {
        "cats": [
          12
        ],
        "implies": "Handlebars",
        "js": {
          "Ember": "",
          "Ember.VERSION": "^(.+)$\\;version:\\1"
        }
      },
      "Ensighten": {
        "cats": [
          42
        ],
        "script": "//nexus\\.ensighten\\.com/"
      },
      "Envoy": {
        "cats": [
          64
        ],
        "headers": {
          "Server": "^envoy$",
          "x-envoy-upstream-service-time": ""
        }
      },
      "Enyo": {
        "cats": [
          12,
          26
        ],
        "js": {
          "enyo": ""
        },
        "script": "enyo\\.js"
      },
      "Epoch": {
        "cats": [
          25
        ],
        "html": "<link[^>]+?href=\"[^\"]+epoch(?:\\.min)?\\.css",
        "implies": "D3",
        "script": "epoch(?:\\.min)?\\.js"
      },
      "Epom": {
        "cats": [
          36
        ],
        "js": {
          "epomCustomParams": ""
        },
        "url": "^https?://(?:[^/]+\\.)?ad(?:op)?shost1\\.com/"
      },
      "Erlang": {
        "cats": [
          27
        ],
        "headers": {
          "Server": "Erlang( OTP/(?:[\\d.ABR-]+))?\\;version:\\1"
        }
      },
      "Etherpad": {
        "cats": [
          24
        ],
        "headers": {
          "Server": "^Etherpad"
        },
        "implies": "Node.js",
        "js": {
          "padeditbar": "",
          "padimpexp": ""
        },
        "script": [
          "/ep_etherpad-lite/"
        ]
      },
      "Exhibit": {
        "cats": [
          25
        ],
        "js": {
          "Exhibit": "",
          "Exhibit.version": "^(.+)$\\;version:\\1"
        },
        "script": "exhibit.*\\.js"
      },
      "Express": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "X-Powered-By": "^Express$"
        },
        "implies": "Node.js"
      },
      "ExpressionEngine": {
        "cats": [
          1
        ],
        "cookies": {
          "exp_csrf_token": "",
          "exp_last_activity": "",
          "exp_tracker": ""
        },
        "implies": "PHP"
      },
      "ExtJS": {
        "cats": [
          12
        ],
        "js": {
          "Ext": "",
          "Ext.version": "^(.+)$\\;version:\\1",
          "Ext.versions.extjs.version": "^(.+)$\\;version:\\1"
        },
        "script": "ext-base\\.js"
      },
      "F5 BigIP": {
        "cats": [
          64
        ],
        "headers": {
          "server": "^big-?ip$"
        },
        "cookies": {
          "F5_ST": "",
          "MRHSHint": "",
          "F5_HT_shrinked": "",
          "F5_fullWT": "",
          "MRHSequence": "",
          "MRHSession": "",
          "LastMRH_Session": "",
          "TIN": ""
        }
      },
      "FAST ESP": {
        "cats": [
          29
        ],
        "html": "<form[^>]+id=\"fastsearch\""
      },
      "FAST Search for SharePoint": {
        "cats": [
          29
        ],
        "html": "<input[^>]+ name=\"ParametricSearch",
        "implies": [
          "Microsoft SharePoint",
          "Microsoft ASP.NET"
        ],
        "url": "Pages/SearchResults\\.aspx\\?k="
      },
      "FWP": {
        "cats": [
          6
        ],
        "html": "<!--\\s+FwP Systems",
        "meta": {
          "generator": "FWP Shop"
        }
      },
      "Facebook": {
        "cats": [
          5
        ],
        "script": "//connect\\.facebook\\.net/[^/]*/[a-z]*\\.js"
      },
      "Fact Finder": {
        "cats": [
          29
        ],
        "html": "<!-- Factfinder",
        "script": "Suggest\\.ff",
        "url": "(?:/ViewParametricSearch|ffsuggest\\.[a-z]htm)"
      },
      "FancyBox": {
        "cats": [
          59
        ],
        "implies": "jQuery",
        "js": {
          "$.fancybox.version": "^(.+)$\\;version:\\1"
        },
        "script": "jquery\\.fancybox(?:\\.pack|\\.min)?\\.js(?:\\?v=([\\d.]+))?$\\;version:\\1"
      },
      "Fastcommerce": {
        "cats": [
          6
        ],
        "meta": {
          "generator": "^Fastcommerce"
        }
      },
      "Fastly": {
        "cats": [
          31
        ],
        "headers": {
          "Fastly-Debug-Digest": "",
          "Vary": "Fastly-SSL",
          "x-via-fastly:": "",
          "X-Fastly-Request-ID": ""
        }
      },
      "Fat-Free Framework": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "^Fat-Free Framework$"
        },
        "implies": "PHP"
      },
      "Fbits": {
        "cats": [
          6
        ],
        "js": {
          "fbits": ""
        }
      },
      "Fedora": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "Fedora"
        }
      },
      "Fingerprintjs": {
        "cats": [
          59
        ],
        "js": {
          "Fingerprint": "(\\d)?$\\;version:\\1",
          "Fingerprint2": "",
          "Fingerprint2.VERSION": "^(.+)$\\;version:\\1"
        },
        "script": "fingerprint(\\d)?(?:\\.min)?\\.js\\;version:\\1"
      },
      "Firebase": {
        "cats": [
          34
        ],
        "js": {
          "firebase.SDK_VERSION": "([\\d.]+)$\\;version:\\1"
        },
        "script": "/(?:([\\d.]+)/)?firebase(?:\\.min)?\\.js\\;version:\\1"
      },
      "Fireblade": {
        "cats": [
          31
        ],
        "headers": {
          "Server": "fbs"
        }
      },
      "Flarum": {
        "cats": [
          2
        ],
        "html": "<div id=\"flarum-loading\"",
        "implies": [
          "PHP",
          "MySQL"
        ],
        "js": {
          "app.cache.discussionList": "",
          "app.forum.freshness": ""
        }
      },
      "Flask": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "Server": "Werkzeug/?([\\d\\.]+)?\\;version:\\1"
        },
        "implies": "Python"
      },
      "Flat UI": {
        "cats": [
          18
        ],
        "html": "<link[^>]* href=[^>]+flat-ui(?:\\.min)?\\.css",
        "implies": "Bootstrap"
      },
      "FlexCMP": {
        "cats": [
          1
        ],
        "headers": {
          "X-Flex-Lang": "",
          "X-Powered-By": "FlexCMP.+\\[v\\. ([\\d.]+)\\;version:\\1"
        },
        "html": "<!--[^>]+FlexCMP[^>v]+v\\. ([\\d.]+)\\;version:\\1",
        "meta": {
          "generator": "^FlexCMP"
        }
      },
      "FlexSlider": {
        "cats": [
          5
        ],
        "implies": "jQuery",
        "script": [
          "jquery\\.flexslider(?:\\.min)?\\.js$"
        ]
      },
      "Flickity": {
        "cats": [
          59
        ],
        "js": {
          "Flickity": ""
        },
        "script": "/flickity(?:\\.pkgd)?(?:\\.min)?\\.js"
      },
      "FluxBB": {
        "cats": [
          2
        ],
        "html": "<p id=\"poweredby\">[^<]+<a href=\"https?://fluxbb\\.org/\">",
        "implies": "PHP"
      },
      "Flyspray": {
        "cats": [
          13
        ],
        "cookies": {
          "flyspray_project": ""
        },
        "html": "(?:<a[^>]+>Powered by Flyspray|<map id=\"projectsearchform)",
        "implies": "PHP"
      },
      "Font Awesome": {
        "cats": [
          17
        ],
        "html": [
          "<link[^>]* href=[^>]+(?:([\\d.]+)/)?(?:css/)?font-awesome(?:\\.min)?\\.css\\;version:\\1",
          "<script[^>]* src=[^>]+fontawesome(?:\\.js)?"
        ]
      },
      "Fork CMS": {
        "cats": [
          1
        ],
        "implies": "Symfony",
        "meta": {
          "generator": "^Fork CMS$"
        }
      },
      "Fortune3": {
        "cats": [
          6
        ],
        "html": "(?:<link [^>]*href=\"[^\\/]*\\/\\/www\\.fortune3\\.com\\/[^\"]*siterate\\/rate\\.css|Powered by <a [^>]*href=\"[^\"]+fortune3\\.com)",
        "script": "cartjs\\.php\\?(?:.*&)?s=[^&]*myfortune3cart\\.com"
      },
      "Foswiki": {
        "cats": [
          8
        ],
        "cookies": {
          "FOSWIKISTRIKEONE": "",
          "SFOSWIKISID": ""
        },
        "headers": {
          "X-Foswikiaction": "",
          "X-Foswikiuri": ""
        },
        "html": [
          "<div class=\"foswiki(?:Copyright|Page|Main)\">"
        ],
        "implies": "Perl",
        "js": {
          "foswiki": ""
        },
        "meta": {
          "foswiki.SERVERTIME": "",
          "foswiki.WIKINAME": ""
        }
      },
      "FreeBSD": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "FreeBSD(?: ([\\d.]+))?\\;version:\\1"
        }
      },
      "FreeTextBox": {
        "cats": [
          24
        ],
        "html": "/<!--\\s*\\*\\s*FreeTextBox v\\d+ \\(([.\\d]+)(?:(?:.|\\n)+?<!--\\s*\\*\\s*License Type: (Distribution|Professional)License)?/i\\;version:\\1 \\2",
        "implies": "Microsoft ASP.NET",
        "js": {
          "FTB_API": "",
          "FTB_AddEvent": ""
        }
      },
      "Freespee": {
        "cats": [
          10
        ],
        "script": "analytics\\.freespee\\.com/js/external/fs\\.(?:min\\.)?js"
      },
      "Freshchat": {
        "cats": [
          52
        ],
        "script": "wchat\\.freshchat\\.com/js/widget\\.js"
      },
      "Freshmarketer": {
        "cats": [
          10
        ],
        "script": "cdn\\.freshmarketer\\.com"
      },
      "Froala Editor": {
        "cats": [
          24
        ],
        "html": "<[^>]+class=\"[^\"]*(?:fr-view|fr-box)",
        "implies": [
          "jQuery",
          "Font Awesome"
        ]
      },
      "FrontPage": {
        "cats": [
          20
        ],
        "meta": {
          "ProgId": "^FrontPage\\.",
          "generator": "Microsoft FrontPage(?:\\s((?:Express )?[\\d.]+))?\\;version:\\1"
        }
      },
      "Fusion Ads": {
        "cats": [
          36
        ],
        "js": {
          "_fusion": ""
        },
        "script": "^[^\\/]*//[ac]dn\\.fusionads\\.net/(?:api/([\\d.]+)/)?\\;version:\\1"
      },
      "Future Shop": {
        "cats": [
          6
        ],
        "script": "future-shop.*\\.js"
      },
      "G-WAN": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "G-WAN"
        }
      },
      "GX WebManager": {
        "cats": [
          1
        ],
        "html": "<!--\\s+Powered by GX",
        "meta": {
          "generator": "GX WebManager(?: ([\\d.]+))?\\;version:\\1"
        }
      },
      "Gallery": {
        "cats": [
          7
        ],
        "html": [
          "<div id=\"gsNavBar\" class=\"gcBorder1\">",
          "<a href=\"http://gallery\\.sourceforge\\.net\"><img[^>]+Powered by Gallery\\s*(?:(?:v|Version)\\s*([0-9.]+))?\\;version:\\1"
        ],
        "js": {
          "$.fn.gallery_valign": "",
          "galleryAuthToken": ""
        }
      },
      "Gambio": {
        "cats": [
          6
        ],
        "html": "(?:<link[^>]* href=\"templates/gambio/|<a[^>]content\\.php\\?coID=\\d|<!-- gambio eof -->|<!--[\\s=]+Shopsoftware by Gambio GmbH \\(c\\))",
        "implies": "PHP",
        "js": {
          "gambio": ""
        },
        "script": "gm_javascript\\.js\\.php"
      },
      "Gatsby": {
        "cats": [
          57,
          12
        ],
        "html": [
          "<div id=\"___gatsby\">",
          "<style id=\"gatsby-inlined-css\">"
        ],
        "meta": {
          "generator": "^Gatsby(?: ([0-9.]+))?$\\;version:\\1"
        },
        "implies": [
          "React",
          "webpack"
        ]
      },
      "Gauges": {
        "cats": [
          10
        ],
        "cookies": {
          "_gauges_": ""
        },
        "js": {
          "_gauges": ""
        }
      },
      "Gentoo": {
        "cats": [
          28
        ],
        "headers": {
          "X-Powered-By": "gentoo"
        }
      },
      "Gerrit": {
        "cats": [
          47
        ],
        "html": [
          ">Gerrit Code Review</a>\\s*\"\\s*\\(([0-9.]+)\\)\\;version:\\1",
          "<(?:div|style) id=\"gerrit_"
        ],
        "implies": [
          "Java",
          "git"
        ],
        "js": {
          "Gerrit": "",
          "gerrit_ui": ""
        },
        "meta": {
          "title": "^Gerrit Code Review$"
        },
        "script": "^gerrit_ui/gerrit_ui"
      },
      "Get Satisfaction": {
        "cats": [
          13
        ],
        "js": {
          "GSFN": ""
        }
      },
      "GetSimple CMS": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "GetSimple"
        }
      },
      "Ghost": {
        "cats": [
          11
        ],
        "headers": {
          "X-Ghost-Cache-Status": ""
        },
        "implies": "Node.js",
        "meta": {
          "generator": "Ghost(?:\\s([\\d.]+))?\\;version:\\1"
        }
      },
      "GitBook": {
        "cats": [
          4
        ],
        "meta": {
          "generator": "GitBook(?:.([\\d.]+))?\\;version:\\1"
        },
        "url": "^https?://[^/]+\\.gitbook\\.com/"
      },
      "GitHub Pages": {
        "cats": [
          31
        ],
        "headers": {
          "Server": "^GitHub\\.com$",
          "X-GitHub-Request-Id": ""
        },
        "implies": "Ruby on Rails",
        "url": "^https?://[^/]+\\.github\\.io/"
      },
      "GitLab": {
        "cats": [
          13,
          47
        ],
        "cookies": {
          "_gitlab_session": ""
        },
        "html": [
          "<meta content=\"https?://[^/]+/assets/gitlab_logo-",
          "<header class=\"navbar navbar-fixed-top navbar-gitlab with-horizontal-nav\">"
        ],
        "implies": "Ruby on Rails",
        "js": {
          "GitLab": "",
          "gl.dashboardOptions": ""
        },
        "meta": {
          "og:site_name": "^GitLab$"
        }
      },
      "GitLab CI": {
        "cats": [
          44,
          47
        ],
        "implies": "Ruby on Rails",
        "meta": {
          "description": "GitLab Continuous Integration"
        }
      },
      "Gitea": {
        "cats": [
          47
        ],
        "cookies": {
          "i_like_gitea": ""
        },
        "html": [
          "<div class=\"ui left\">\\n\\s+© Gitea Version: ([\\d.]+)\\;version:\\1"
        ],
        "meta": {
          "keywords": "^go,git,self-hosted,gitea$"
        }
      },
      "Gitiles": {
        "cats": [
          47
        ],
        "html": "Powered by <a href=\"https://gerrit\\.googlesource\\.com/gitiles/\">Gitiles<",
        "implies": [
          "Java",
          "git"
        ]
      },
      "GlassFish": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "GlassFish(?: Server)?(?: Open Source Edition)?(?: ?/?([\\d.]+))?\\;version:\\1"
        },
        "implies": [
          "Java"
        ]
      },
      "Glyphicons": {
        "cats": [
          17
        ],
        "html": "(?:<link[^>]* href=[^>]+glyphicons(?:\\.min)?\\.css|<img[^>]* src=[^>]+glyphicons)"
      },
      "Go": {
        "cats": [
          27
        ]
      },
      "GoAhead": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "GoAhead"
        }
      },
      "GoJS": {
        "cats": [
          25
        ],
        "website": "https://gojs.net/",
        "js": {
          "go.version": "(.*)\\;version:\\1",
          "go.GraphObject": ""
        }
      },
      "GoSquared": {
        "cats": [
          10,
          52,
          53
        ],
        "js": {
          "_gs": "\\;confidence:30"
        }
      },
      "GoStats": {
        "cats": [
          10
        ],
        "js": {
          "_goStatsRun": "",
          "_go_track_src": "",
          "go_msie": ""
        }
      },
      "Gogs": {
        "cats": [
          47
        ],
        "cookies": {
          "i_like_gogits": ""
        },
        "html": [
          "<div class=\"ui left\">\\n\\s+© \\d{4} Gogs Version: ([\\d.]+) Page:\\;version:\\1",
          "<button class=\"ui basic clone button\" id=\"repo-clone-ssh\" data-link=\"gogs@"
        ],
        "meta": {
          "keywords": "go, git, self-hosted, gogs"
        },
        "script": "js/gogs\\.js"
      },
      "Google AdSense": {
        "cats": [
          36
        ],
        "js": {
          "Goog_AdSense_": "",
          "__google_ad_urls": "",
          "google_ad_": ""
        },
        "script": [
          "googlesyndication\\.com/",
          "ad\\.ca\\.doubleclick\\.net",
          "2mdn\\.net",
          "ad\\.ca\\.doubleclick\\.net"
        ]
      },
      "Google Analytics": {
        "cats": [
          10
        ],
        "cookies": {
          "__utma": "",
          "_ga": "",
          "_gat": ""
        },
        "html": "<amp-analytics [^>]*type=[\"']googleanalytics[\"']",
        "js": {
          "GoogleAnalyticsObject": "",
          "gaGlobal": ""
        },
        "script": "google-analytics\\.com\\/(?:ga|urchin|analytics)\\.js"
      },
      "Google Analytics Enhanced eCommerce": {
        "cats": [
          10
        ],
        "implies": "Google Analytics",
        "js": {
          "gaplugins.EC": ""
        },
        "script": "google-analytics\\.com\\/plugins\\/ua\\/(?:ec|ecommerce)\\.js"
      },
      "Google App Engine": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Google Frontend"
        }
      },
      "Google Charts": {
        "cats": [
          25
        ],
        "js": {
          "__googleVisualizationAbstractRendererElementsCount__": "",
          "__gvizguard__": ""
        }
      },
      "Google Cloud": {
        "cats": [
          31
        ],
        "headers": {
          "Via": "^1\\.1 google$"
        }
      },
      "Google Code Prettify": {
        "cats": [
          19
        ],
        "js": {
          "prettyPrint": ""
        }
      },
      "Google Font API": {
        "cats": [
          17
        ],
        "html": "<link[^>]* href=[^>]+fonts\\.(?:googleapis|google)\\.com",
        "js": {
          "WebFonts": ""
        },
        "script": "googleapis\\.com/.+webfont"
      },
      "Google Maps": {
        "cats": [
          35
        ],
        "script": [
          "(?:maps\\.google\\.com/maps\\?file=api(?:&v=([\\d.]+))?|maps\\.google\\.com/maps/api/staticmap)\\;version:API v\\1",
          "//maps\\.googleapis\\.com/maps/api/js"
        ]
      },
      "Google PageSpeed": {
        "cats": [
          23,
          33
        ],
        "headers": {
          "X-Mod-Pagespeed": "([\\d.]+)\\;version:\\1",
          "X-Page-Speed": "(.+)\\;version:\\1"
        }
      },
      "Google Plus": {
        "cats": [
          5
        ],
        "script": "apis\\.google\\.com/js/[a-z]*\\.js"
      },
      "Google Sites": {
        "cats": [
          1
        ],
        "url": "^https?://sites\\.google\\.com"
      },
      "Google Tag Manager": {
        "cats": [
          42
        ],
        "html": [
          "googletagmanager\\.com/ns\\.html[^>]+></iframe>",
          "<!-- (?:End )?Google Tag Manager -->"
        ],
        "js": {
          "google_tag_manager": "",
          "googletag": ""
        }
      },
      "Google Wallet": {
        "cats": [
          41
        ],
        "script": [
          "checkout\\.google\\.com",
          "wallet\\.google\\.com"
        ]
      },
      "Google Web Server": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "gws"
        }
      },
      "Google Web Toolkit": {
        "cats": [
          18
        ],
        "implies": "Java",
        "js": {
          "__gwt_": ""
        },
        "meta": {
          "gwt:property": ""
        }
      },
      "Graffiti CMS": {
        "cats": [
          1
        ],
        "cookies": {
          "graffitibot": ""
        },
        "implies": "Microsoft ASP.NET",
        "meta": {
          "generator": "Graffiti CMS ([^\"]+)\\;version:\\1"
        },
        "script": "/graffiti\\.js"
      },
      "Grav": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "GravCMS(?:\\s([\\d.]+))?\\;version:\\1"
        }
      },
      "Gravatar": {
        "cats": [
          19
        ],
        "html": "<[^>]+gravatar\\.com/avatar/",
        "js": {
          "Gravatar": ""
        }
      },
      "Gravity Forms": {
        "cats": [
          19
        ],
        "html": [
          "<div class=(?:\"|')[^>]*gform_wrapper",
          "<div class=(?:\"|')[^>]*gform_body",
          "<ul [^>]*class=(?:\"|')[^>]*gform_fields",
          "<link [^>]*href=(?:\"|')[^>]*wp-content/plugins/gravityforms/css/"
        ],
        "implies": "WordPress",
        "script": "/wp-content/plugins/gravityforms/js/[^/]+\\.js\\?ver=([\\d.]+)$\\;version:\\1"
      },
      "Green Valley CMS": {
        "cats": [
          1
        ],
        "html": "<img[^>]+/dsresource\\?objectid=",
        "implies": "Apache Tomcat",
        "meta": {
          "DC.identifier": "/content\\.jsp\\?objectid="
        }
      },
      "Gridsome": {
        "cats": [
          57
        ],
        "implies": "Vue.js",
        "meta": {
          "generator": "^Gridsome v([\\d.]+)$\\;version:\\1"
        }
      },
      "GrowingIO": {
        "cats": [
          10
        ],
        "js": {
          "gio": ""
        },
        "cookies": {
          "grwng_uid": "",
          "gr_user_id": ""
        },
        "script": "assets\\.growingio\\.com/([\\d.]+)/gio.js\\;version:\\1"
      },
      "HERE": {
        "cats": [
          35
        ],
        "script": "https?://js\\.cit\\.api\\.here\\.com/se/([\\d.]+)\\/\\;version:\\1"
      },
      "HHVM": {
        "cats": [
          22
        ],
        "headers": {
          "X-Powered-By": "HHVM/?([\\d.]+)?\\;version:\\1"
        },
        "implies": "PHP\\;confidence:75"
      },
      "HP ChaiServer": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "HP-Chai(?:Server|SOE)(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "HP Compact Server": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "HP_Compact_Server(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "HP ProCurve": {
        "cats": [
          37
        ]
      },
      "HP System Management": {
        "cats": [
          46
        ],
        "headers": {
          "Server": "HP System Management"
        }
      },
      "HP iLO": {
        "cats": [
          22,
          46
        ],
        "headers": {
          "Server": "HP-iLO-Server(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "HTTP/2": {
        "cats": [
          19
        ],
        "excludes": "SPDY",
        "headers": {
          "X-Firefox-Spdy": "h2"
        }
      },
      "Haddock": {
        "cats": [
          4
        ],
        "html": "<p>Produced by <a href=\"http://www\\.haskell\\.org/haddock/\">Haddock</a> version ([0-9.]+)</p>\\;version:\\1",
        "script": "haddock-util\\.js"
      },
      "Hammer.js": {
        "cats": [
          59
        ],
        "js": {
          "Ha.VERSION": "^(.+)$\\;version:\\1",
          "Hammer": "",
          "Hammer.VERSION": "^(.+)$\\;version:\\1"
        },
        "script": "hammer(?:\\.min)?\\.js"
      },
      "Handlebars": {
        "cats": [
          12
        ],
        "html": "<[^>]*type=[^>]text\\/x-handlebars-template",
        "js": {
          "Handlebars": "",
          "Handlebars.VERSION": "^(.+)$\\;version:\\1"
        },
        "script": "handlebars(?:\\.runtime)?(?:-v([\\d.]+?))?(?:\\.min)?\\.js\\;version:\\1"
      },
      "Haravan": {
        "cats": [
          6
        ],
        "js": {
          "Haravan": ""
        },
        "script": "haravan.*\\.js"
      },
      "Haskell": {
        "cats": [
          27
        ]
      },
      "HeadJS": {
        "cats": [
          59
        ],
        "html": "<[^>]*data-headjs-load",
        "js": {
          "head.browser.name": ""
        },
        "script": "head\\.(?:core|load)(?:\\.min)?\\.js"
      },
      "Heap": {
        "cats": [
          10
        ],
        "js": {
          "heap": ""
        },
        "script": "heap-\\d+\\.js"
      },
      "Hello Bar": {
        "cats": [
          5
        ],
        "js": {
          "HelloBar": ""
        },
        "script": "hellobar\\.js"
      },
      "Hexo": {
        "cats": [
          57
        ],
        "html": [
          "Powered by <a href=\"https?://hexo\\.io/?\"[^>]*>Hexo</"
        ],
        "meta": {
          "generator": "Hexo(?: v?([\\d.]+))?\\;version:\\1"
        }
      },
      "Hiawatha": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Hiawatha v([\\d.]+)\\;version:\\1"
        }
      },
      "Highcharts": {
        "cats": [
          25
        ],
        "html": "<svg[^>]*><desc>Created with Highcharts ([\\d.]*)\\;version:\\1",
        "js": {
          "Highcharts": "",
          "Highcharts.version": "^(.+)$\\;version:\\1"
        },
        "script": "highcharts.*\\.js"
      },
      "Highlight.js": {
        "cats": [
          19
        ],
        "js": {
          "hljs.highlightBlock": "",
          "hljs.listLanguages": ""
        },
        "script": "/(?:([\\d.])+/)?highlight(?:\\.min)?\\.js\\;version:\\1"
      },
      "Highstock": {
        "cats": [
          25
        ],
        "html": "<svg[^>]*><desc>Created with Highstock ([\\d.]*)\\;version:\\1",
        "script": "highstock[.-]?([\\d\\.]*\\d).*\\.js\\;version:\\1"
      },
      "Hinza Advanced CMS": {
        "cats": [
          1,
          6
        ],
        "implies": "Laravel",
        "meta": {
          "generator": "hinzacms"
        }
      },
      "Bloomreach": {
        "cats": [
          1
        ],
        "html": "<[^>]+/binaries/(?:[^/]+/)*content/gallery/"
      },
      "Hogan.js": {
        "cats": [
          12
        ],
        "js": {
          "Hogan": ""
        },
        "script": [
          "hogan-[.-]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "([\\d.]+)/hogan(?:\\.min)?\\.js\\;version:\\1"
        ]
      },
      "Homeland": {
        "cats": [
          1,
          2
        ],
        "cookies": {
          "_homeland_": ""
        },
        "implies": "Ruby on Rails"
      },
      "Hotaru CMS": {
        "cats": [
          1
        ],
        "cookies": {
          "hotaru_mobile": ""
        },
        "implies": "PHP",
        "meta": {
          "generator": "Hotaru CMS"
        }
      },
      "Hotjar": {
        "cats": [
          10
        ],
        "js": {
          "HotLeadfactory": "",
          "HotleadController": "",
          "hj.apiUrlBase": ""
        },
        "script": "^//static\\.hotjar\\.com/c/hotjar-"
      },
      "HubSpot": {
        "cats": [
          32
        ],
        "html": "<!-- Start of Async HubSpot",
        "js": {
          "_hsq": "",
          "hubspot": ""
        }
      },
      "Hugo": {
        "cats": [
          57
        ],
        "html": "powered by <a [^>]*href=\"http://hugo.spf13.com",
        "meta": {
          "generator": "Hugo ([\\d.]+)?\\;version:\\1"
        }
      },
      "Hybris": {
        "cats": [
          6
        ],
        "cookies": {
          "_hybris": ""
        },
        "html": "<[^>]+/(?:sys_master|hybr|_ui/(?:responsive/)?(?:desktop|common(?:/images|/img)?))/",
        "implies": "Java"
      },
      "IBM Coremetrics": {
        "cats": [
          10
        ],
        "script": "cmdatatagutils\\.js"
      },
      "IBM DataPower": {
        "cats": [
          64
        ],
        "headers": {
          "X-Backside-Transport": "",
          "X-Global-Transaction-ID": ""
        }
      },
      "IBM HTTP Server": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "IBM_HTTP_Server(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "IBM Tivoli Storage Manager": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "TSM_HTTP(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "IBM WebSphere Commerce": {
        "cats": [
          6
        ],
        "html": "href=\"(?:\\/|[^>]+)webapp\\/wcs\\/",
        "implies": "Java",
        "url": "/wcs/"
      },
      "IBM WebSphere Portal": {
        "cats": [
          1
        ],
        "headers": {
          "IBM-Web2-Location": "",
          "Itx-Generated-Timestamp": ""
        },
        "implies": "Java",
        "url": "/wps/"
      },
      "IIS": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^(?:Microsoft-)?IIS(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": "Windows Server"
      },
      "INFOnline": {
        "cats": [
          10
        ],
        "js": {
          "iam_data": "",
          "szmvars": ""
        },
        "script": "^https?://(?:[^/]+\\.)?i(?:oam|v)wbox\\.de/"
      },
      "INTI": {
        "cats": [
          6,
          53
        ],
        "url": "\\.byinti\\.com"
      },
      "IPB": {
        "cats": [
          2
        ],
        "cookies": {
          "ipbWWLmodpids": "",
          "ipbWWLsession_id": ""
        },
        "html": "<link[^>]+ipb_[^>]+\\.css",
        "implies": [
          "PHP",
          "MySQL"
        ],
        "js": {
          "IPBoard": "",
          "ipb_var": "",
          "ipsSettings": ""
        },
        "script": "jscripts/ips_"
      },
      "Ideasoft": {
        "cats": [
          6
        ],
        "script": [
          "\\.myideasoft\\.com/"
        ]
      },
      "IdoSell Shop": {
        "cats": [
          6
        ],
        "js": {
          "IAI_Ajax": ""
        }
      },
      "Immutable.js": {
        "cats": [
          59
        ],
        "js": {
          "Immutable": "",
          "Immutable.version": "^(.+)$\\;version:\\1"
        },
        "script": "^immutable\\.(?:min\\.)?js$"
      },
      "ImpressCMS": {
        "cats": [
          1
        ],
        "cookies": {
          "ICMSSession": "",
          "ImpressCMS": ""
        },
        "implies": "PHP",
        "meta": {
          "generator": "ImpressCMS"
        },
        "script": "include/linkexternal\\.js"
      },
      "ImpressPages": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "ImpressPages(?: CMS)?( [\\d.]*)?\\;version:\\1"
        }
      },
      "InProces": {
        "cats": [
          1
        ],
        "html": "<!-- CSS InProces Portaal default -->",
        "script": "brein/inproces/website/websitefuncties\\.js"
      },
      "Incapsula": {
        "cats": [
          31
        ],
        "headers": {
          "X-CDN": "Incapsula"
        }
      },
      "Includable": {
        "cats": [
          18
        ],
        "headers": {
          "X-Includable-Version": ""
        }
      },
      "Indexhibit": {
        "cats": [
          1
        ],
        "html": "<(?:link|a href) [^>]+ndxz-studio",
        "implies": [
          "PHP",
          "Apache",
          "Exhibit"
        ],
        "meta": {
          "generator": "Indexhibit"
        }
      },
      "Indico": {
        "cats": [
          1
        ],
        "cookies": {
          "MAKACSESSION": ""
        },
        "html": "Powered by\\s+(?:CERN )?<a href=\"http://(?:cdsware\\.cern\\.ch/indico/|indico-software\\.org|cern\\.ch/indico)\">(?:CDS )?Indico( [\\d\\.]+)?\\;version:\\1"
      },
      "Indy": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Indy(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "InfernoJS": {
        "cats": [
          12
        ],
        "js": {
          "Inferno": "",
          "Inferno.version": "^(.+)$\\;version:\\1"
        }
      },
      "Infusionsoft": {
        "cats": [
          32
        ],
        "html": [
          "<input [^>]*name=\"infusionsoft_version\" [^>]*value=\"([^>]*)\" [^>]*\\/>\\;version:\\1",
          "<input [^>]*value=\"([^>]*)\" [^>]*name=\"infusionsoft_version\" [^>]*\\/>\\;version:\\1"
        ]
      },
      "Inspectlet": {
        "cats": [
          10
        ],
        "html": [
          "<!-- (?:Begin|End) Inspectlet Embed Code -->"
        ],
        "js": {
          "__insp": "",
          "__inspld": ""
        },
        "script": [
          "cdn\\.inspectlet\\.com"
        ]
      },
      "Instabot": {
        "cats": [
          5,
          10,
          32,
          52,
          58
        ],
        "js": {
          "Instabot": ""
        },
        "script": "/rokoInstabot\\.js"
      },
      "InstantCMS": {
        "cats": [
          1
        ],
        "cookies": {
          "InstantCMS[logdate]": ""
        },
        "implies": "PHP",
        "meta": {
          "generator": "InstantCMS"
        }
      },
      "Intel Active Management Technology": {
        "cats": [
          22,
          46
        ],
        "headers": {
          "Server": "Intel\\(R\\) Active Management Technology(?: ([\\d.]+))?\\;version:\\1"
        }
      },
      "IntenseDebate": {
        "cats": [
          15
        ],
        "script": "intensedebate\\.com"
      },
      "Intercom": {
        "cats": [
          10
        ],
        "js": {
          "Intercom": ""
        },
        "script": "(?:api\\.intercom\\.io/api|static\\.intercomcdn\\.com/intercom\\.v1)"
      },
      "Intershop": {
        "cats": [
          6
        ],
        "script": "(?:is-bin|INTERSHOP)"
      },
      "Invenio": {
        "cats": [
          50
        ],
        "cookies": {
          "INVENIOSESSION": ""
        },
        "html": "(?:Powered by|System)\\s+(?:CERN )?<a (?:class=\"footer\" )?href=\"http://(?:cdsware\\.cern\\.ch(?:/invenio)?|invenio-software\\.org|cern\\.ch/invenio)(?:/)?\">(?:CDS )?Invenio</a>\\s*v?([\\d\\.]+)?\\;version:\\1"
      },
      "Inwemo": {
        "cats": [
          56
        ],
        "js": {
          "Inwemo": ""
        },
        "script": "https?://cdn\\.inwemo\\.com/inwemo\\.min\\.js"
      },
      "Ionic": {
        "cats": [
          18
        ],
        "implies": "Angular",
        "js": {
          "Ionic.config": "",
          "Ionic.version": "^(.+)$\\;version:\\1"
        }
      },
      "Ionicons": {
        "cats": [
          17
        ],
        "html": "<link[^>]* href=[^>]+ionicons(?:\\.min)?\\.css"
      },
      "JAlbum": {
        "cats": [
          7
        ],
        "implies": "Java",
        "meta": {
          "generator": "JAlbum( [\\d.]+)?\\;version:\\1"
        }
      },
      "JBoss Application Server": {
        "cats": [
          22
        ],
        "headers": {
          "X-Powered-By": "JBoss(?:-([\\d.]+))?\\;version:\\1"
        }
      },
      "JBoss Web": {
        "cats": [
          22
        ],
        "excludes": "Apache Tomcat",
        "headers": {
          "X-Powered-By": "JBossWeb(?:-([\\d.]+))?\\;version:\\1"
        },
        "implies": "JBoss Application Server"
      },
      "JET Enterprise": {
        "cats": [
          6
        ],
        "headers": {
          "powered": "jet-enterprise"
        }
      },
      "JS Charts": {
        "cats": [
          25
        ],
        "js": {
          "JSChart": ""
        },
        "script": "jscharts.*\\.js"
      },
      "JSEcoin": {
        "cats": [
          56
        ],
        "js": {
          "jseMine": ""
        },
        "script": "^(?:https):?//load\\.jsecoin\\.com/load/"
      },
      "JTL Shop": {
        "cats": [
          6
        ],
        "cookies": {
          "JTLSHOP": ""
        },
        "html": "(?:<input[^>]+name=\"JTLSHOP|<a href=\"jtl\\.php)"
      },
      "Jahia DX": {
        "cats": [
          1,
          47
        ],
        "html": "<script id=\"staticAssetAggregatedJavascrip"
      },
      "Jalios": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "Jalios"
        }
      },
      "Java": {
        "cats": [
          27
        ],
        "cookies": {
          "JSESSIONID": ""
        }
      },
      "Java Servlet": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "Servlet(?:.([\\d.]+))?\\;version:\\1"
        },
        "implies": "Java"
      },
      "JavaScript Infovis Toolkit": {
        "cats": [
          25
        ],
        "js": {
          "$jit": "",
          "$jit.version": "^(.+)$\\;version:\\1"
        },
        "script": "jit(?:-yc)?\\.js"
      },
      "JavaServer Faces": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "JSF(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": "Java"
      },
      "JavaServer Pages": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "JSP(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": "Java"
      },
      "Jekyll": {
        "cats": [
          57
        ],
        "html": [
          "Powered by <a href=\"https?://jekyllrb\\.com\"[^>]*>Jekyll</",
          "<!-- Created with Jekyll Now -",
          "<!-- Begin Jekyll SEO tag"
        ],
        "meta": {
          "generator": "Jekyll (v[\\d.]+)?\\;version:\\1"
        }
      },
      "Jenkins": {
        "cats": [
          44
        ],
        "headers": {
          "X-Jenkins": "([\\d.]+)\\;version:\\1"
        },
        "html": "<span class=\"jenkins_ver\"><a href=\"https://jenkins\\.io/\">Jenkins ver\\. ([\\d.]+)\\;version:\\1",
        "implies": "Java",
        "js": {
          "jenkinsCIGlobal": "",
          "jenkinsRules": ""
        }
      },
      "Jetshop": {
        "cats": [
          6
        ],
        "html": "<(?:div|aside) id=\"jetshop-branding\">",
        "js": {
          "JetshopData": ""
        }
      },
      "Jetty": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Jetty(?:\\(([\\d\\.]*\\d+))?\\;version:\\1"
        },
        "implies": "Java"
      },
      "Jimdo": {
        "cats": [
          1
        ],
        "headers": {
          "X-Jimdo-Instance": "",
          "X-Jimdo-Wid": ""
        },
        "url": "\\.jimdo\\.com/",
        "js": {
          "jimdoData": "",
          "jimdo_Data": ""
        }
      },
      "Jirafe": {
        "cats": [
          10,
          32
        ],
        "js": {
          "jirafe": ""
        },
        "script": "/jirafe\\.js"
      },
      "Jive": {
        "cats": [
          19
        ],
        "headers": {
          "X-JIVE-USER-ID": "",
          "X-JSL": "",
          "X-Jive-Flow-Id": "",
          "X-Jive-Request-Id": "",
          "x-jive-chrome-wrapped": ""
        }
      },
      "JobberBase": {
        "cats": [
          19
        ],
        "implies": "PHP",
        "js": {
          "Jobber": ""
        },
        "meta": {
          "generator": "Jobberbase"
        }
      },
      "Joomla": {
        "cats": [
          1
        ],
        "headers": {
          "X-Content-Encoded-By": "Joomla! ([\\d.]+)\\;version:\\1"
        },
        "html": "(?:<div[^>]+id=\"wrapper_r\"|<(?:link|script)[^>]+(?:feed|components)/com_|<table[^>]+class=\"pill)\\;confidence:50",
        "implies": "PHP",
        "js": {
          "Joomla": "",
          "jcomments": ""
        },
        "meta": {
          "generator": "Joomla!(?: ([\\d.]+))?\\;version:\\1"
        },
        "url": "option=com_"
      },
      "K2": {
        "cats": [
          19
        ],
        "html": "<!--(?: JoomlaWorks \"K2\"| Start K2)",
        "implies": "Joomla",
        "js": {
          "K2RatingURL": ""
        }
      },
      "KISSmetrics": {
        "cats": [
          10
        ],
        "js": {
          "KM_COOKIE_DOMAIN": ""
        }
      },
      "Kajabi": {
        "cats": [
          6
        ],
        "cookies": {
          "_kjb_session": ""
        },
        "js": {
          "Kajabi": ""
        }
      },
      "Kampyle": {
        "cats": [
          10,
          13
        ],
        "cookies": {
          "k_visit": ""
        },
        "js": {
          "KAMPYLE_COMMON": "",
          "k_track": "",
          "kampyle": ""
        },
        "script": "cf\\.kampyle\\.com/k_button\\.js"
      },
      "Kamva": {
        "cats": [
          6
        ],
        "js": {
          "Kamva": ""
        },
        "meta": {
          "generator": "[CK]amva"
        },
        "script": "cdn\\.mykamva\\.ir"
      },
      "Kemal": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "X-Powered-By": "Kemal"
        }
      },
      "Kendo UI": {
        "cats": [
          18
        ],
        "html": "<link[^>]*\\s+href=[^>]*styles/kendo\\.common(?:\\.min)?\\.css[^>]*/>",
        "implies": "jQuery",
        "js": {
          "kendo": "",
          "kendo.version": "^(.+)$\\;version:\\1"
        }
      },
      "Kentico CMS": {
        "cats": [
          1
        ],
        "cookies": {
          "CMSPreferredCulture": ""
        },
        "meta": {
          "generator": "Kentico CMS ([\\d.R]+ \\(build [\\d.]+\\))\\;version:\\1"
        }
      },
      "Kestrel": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^Kestrel"
        },
        "implies": [
          "Microsoft ASP.NET"
        ]
      },
      "KeyCDN": {
        "cats": [
          31
        ],
        "headers": {
          "Server": "^keycdn-engine$"
        }
      },
      "Kibana": {
        "cats": [
          29,
          25
        ],
        "headers": {
          "kbn-name": "kibana",
          "kbn-version": "^([\\d.]+)$\\;version:\\1"
        },
        "html": "<title>Kibana</title>",
        "implies": "Node.js",
        "url": "kibana#/dashboard/"
      },
      "KineticJS": {
        "cats": [
          25
        ],
        "js": {
          "Kinetic": "",
          "Kinetic.version": "^(.+)$\\;version:\\1"
        },
        "script": "kinetic(?:-v?([\\d.]+))?(?:\\.min)?\\.js\\;version:\\1"
      },
      "Klarna Checkout": {
        "cats": [
          41,
          6,
          5
        ],
        "js": {
          "_klarnaCheckout": ""
        }
      },
      "Knockout.js": {
        "cats": [
          12
        ],
        "js": {
          "ko.version": "^(.+)$\\;version:\\1"
        }
      },
      "Koa": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "X-Powered-By": "^koa$"
        },
        "implies": "Node.js"
      },
      "Koala Framework": {
        "cats": [
          1,
          18
        ],
        "html": "<!--[^>]+This website is powered by Koala Web Framework CMS",
        "implies": "PHP",
        "meta": {
          "generator": "^Koala Web Framework CMS"
        }
      },
      "KobiMaster": {
        "cats": [
          6
        ],
        "implies": "Microsoft ASP.NET",
        "js": {
          "kmGetSession": "",
          "kmPageInfo": ""
        }
      },
      "Koha": {
        "cats": [
          21
        ],
        "html": [
          "<input name=\"koha_login_context\" value=\"intranet\" type=\"hidden\">",
          "<a href=\"/cgi-bin/koha/"
        ],
        "implies": "Perl",
        "js": {
          "KOHA": ""
        },
        "meta": {
          "generator": "^Koha ([\\d.]+)$\\;version:\\1"
        }
      },
      "Kohana": {
        "cats": [
          18
        ],
        "cookies": {
          "kohanasession": ""
        },
        "headers": {
          "X-Powered-By": "Kohana Framework ([\\d.]+)\\;version:\\1"
        },
        "implies": "PHP"
      },
      "Koken": {
        "cats": [
          1
        ],
        "cookies": {
          "koken_referrer": ""
        },
        "html": [
          "<html lang=\"en\" class=\"k-source-essays k-lens-essays\">",
          "<!--\\s+KOKEN DEBUGGING"
        ],
        "implies": [
          "PHP",
          "MySQL"
        ],
        "meta": {
          "generator": "Koken ([\\d.]+)\\;version:\\1"
        },
        "script": "koken(?:\\.js\\?([\\d.]+)|/storage)\\;version:\\1"
      },
      "Kolibri CMS": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "Kolibri"
        },
        "meta": {
          "generator": "Kolibri"
        }
      },
      "Komodo CMS": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "^Komodo CMS"
        }
      },
      "Kontaktify": {
        "cats": [
          5
        ],
        "script": "//(?:www\\.)?kontaktify\\.com/embed\\.js"
      },
      "Koobi": {
        "cats": [
          1
        ],
        "html": "<!--[^K>-]+Koobi ([a-z\\d.]+)\\;version:\\1",
        "meta": {
          "generator": "Koobi"
        }
      },
      "Kooboo CMS": {
        "cats": [
          1
        ],
        "headers": {
          "X-KoobooCMS-Version": "^(.+)$\\;version:\\1"
        },
        "implies": "Microsoft ASP.NET",
        "script": "/Kooboo"
      },
      "Kotisivukone": {
        "cats": [
          1
        ],
        "script": "kotisivukone(?:\\.min)?\\.js"
      },
      "Kubernetes Dashboard": {
        "cats": [
          47
        ],
        "html": "<html ng-app=\"kubernetesDashboard\">"
      },
      "LEPTON": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "LEPTON"
        }
      },
      "LabVIEW": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "LabVIEW(?:/([\\d\\.]+))?\\;version:\\1"
        }
      },
      "Laravel": {
        "cats": [
          18
        ],
        "cookies": {
          "laravel_session": ""
        },
        "implies": "PHP",
        "js": {
          "Laravel": ""
        }
      },
      "Laterpay": {
        "cats": [
          41
        ],
        "meta": {
          "laterpay:connector:callbacks:on_user_has_access": "deobfuscateText"
        },
        "script": "https?://connectormwi\\.laterpay\\.net/([0-9.]+)[a-zA-z-]*/live/[\\w-]+\\.js\\;version:\\1"
      },
      "Lazy.js": {
        "cats": [
          59
        ],
        "script": "lazy(?:\\.browser)?(?:\\.min)?\\.js"
      },
      "Leaflet": {
        "cats": [
          35
        ],
        "js": {
          "L.DistanceGrid": "",
          "L.PosAnimation": "",
          "L.version": "^(.+)$\\;version:\\1\\;confidence:0"
        },
        "script": "leaflet.*\\.js"
      },
      "Less": {
        "cats": [
          19
        ],
        "html": "<link[^>]+ rel=\"stylesheet/less\""
      },
      "Liferay": {
        "cats": [
          1
        ],
        "headers": {
          "Liferay-Portal": "[a-z\\s]+([\\d.]+)\\;version:\\1"
        },
        "js": {
          "Liferay": ""
        }
      },
      "Lift": {
        "cats": [
          18
        ],
        "headers": {
          "X-Lift-Version": "(.+)\\;version:\\1"
        },
        "implies": "Scala"
      },
      "LightMon Engine": {
        "cats": [
          1
        ],
        "cookies": {
          "lm_online": ""
        },
        "html": "<!-- Lightmon Engine Copyright Lightmon",
        "implies": "PHP",
        "meta": {
          "generator": "LightMon Engine"
        }
      },
      "Lightbox": {
        "cats": [
          59
        ],
        "html": "<link [^>]*href=\"[^\"]+lightbox(?:\\.min)?\\.css",
        "script": "lightbox.*\\.js"
      },
      "Lightspeed eCom": {
        "cats": [
          6
        ],
        "html": "<!-- \\[START\\] 'blocks/head\\.rain' -->",
        "script": "http://assets\\.webshopapp\\.com",
        "url": "seoshop.webshopapp.com"
      },
      "Lighty": {
        "cats": [
          18
        ],
        "cookies": {
          "lighty_version": ""
        },
        "implies": "PHP"
      },
      "LimeSurvey": {
        "cats": [
          19
        ],
        "headers": {
          "generator": "LimeSurvey"
        }
      },
      "LinkSmart": {
        "cats": [
          36
        ],
        "js": {
          "LS_JSON": "",
          "LinkSmart": "",
          "_mb_site_guid": ""
        },
        "script": "^https?://cdn\\.linksmart\\.com/linksmart_([\\d.]+?)(?:\\.min)?\\.js\\;version:\\1"
      },
      "Linkedin": {
        "cats": [
          5
        ],
        "script": "//platform\\.linkedin\\.com/in\\.js"
      },
      "List.js": {
        "cats": [
          59
        ],
        "js": {
          "List": ""
        },
        "script": "^list\\.(?:min\\.)?js$"
      },
      "LiteSpeed": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^LiteSpeed$"
        }
      },
      "Lithium": {
        "cats": [
          1
        ],
        "cookies": {
          "LithiumVisitor": ""
        },
        "html": " <a [^>]+Powered by Lithium",
        "implies": "PHP",
        "js": {
          "LITHIUM": ""
        }
      },
      "LiveAgent": {
        "cats": [
          52
        ],
        "js": {
          "LiveAgent": ""
        }
      },
      "LiveChat": {
        "cats": [
          52
        ],
        "script": "cdn\\.livechatinc\\.com/.*tracking\\.js"
      },
      "LiveHelp": {
        "cats": [
          52,
          53
        ],
        "script": "^https?://server\\.livehelp\\.it/widgetjs/[0-9]{5}/[0-9]{1,3}\\.js"
      },
      "LiveJournal": {
        "cats": [
          11
        ],
        "url": "\\.livejournal\\.com"
      },
      "LivePerson": {
        "cats": [
          52
        ],
        "script": "^https?://lptag\\.liveperson\\.net/tag/tag\\.js"
      },
      "LiveStreet CMS": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "LiveStreet CMS"
        },
        "implies": "PHP",
        "js": {
          "LIVESTREET_SECURITY_KEY": ""
        }
      },
      "Livefyre": {
        "cats": [
          15
        ],
        "html": "<[^>]+(?:id|class)=\"livefyre",
        "js": {
          "FyreLoader": "",
          "L.version": "^(.+)$\\;confidence:0\\;version:\\1",
          "LF.CommentCount": "",
          "fyre": ""
        },
        "script": "livefyre_init\\.js"
      },
      "Liveinternet": {
        "cats": [
          10
        ],
        "html": [
          "<script[^<>]*>[^]{0,128}?src\\s*=\\s*['\"]//counter\\.yadro\\.ru/hit(?:;\\S+)?\\?(?:t\\d+\\.\\d+;)?r",
          "<!--LiveInternet counter-->",
          "<!--/LiveInternet-->",
          "<a href=\"http://www\\.liveinternet\\.ru/click\""
        ],
        "script": "/js/al/common\\.js\\?[0-9_]+"
      },
      "LocalFocus": {
        "cats": [
          61
        ],
        "html": "<iframe[^>]+localfocus",
        "implies": [
          "Angular",
          "D3"
        ]
      },
      "Locomotive": {
        "cats": [
          1
        ],
        "html": "<link[^>]*/sites/[a-z\\d]{24}/theme/stylesheets",
        "implies": [
          "Ruby on Rails",
          "MongoDB"
        ]
      },
      "Lodash": {
        "cats": [
          59
        ],
        "excludes": "Underscore.js",
        "js": {
          "_.VERSION": "^(.+)$\\;confidence:0\\;version:\\1",
          "_.differenceBy": ""
        },
        "script": "lodash.*\\.js"
      },
      "Logitech Media Server": {
        "cats": [
          22,
          38
        ],
        "headers": {
          "Server": "Logitech Media Server(?: \\(([\\d\\.]+))?\\;version:\\1"
        }
      },
      "Lotus Domino": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Lotus-Domino"
        },
        "implies": "Java"
      },
      "LOU": {
        "cats": [
          58
        ],
        "script": "cdn\\.louassist\\.com*"
      },
      "Lua": {
        "cats": [
          27
        ],
        "headers": {
          "X-Powered-By": "\\bLua(?: ([\\d.]+))?\\;version:\\1"
        }
      },
      "Lucene": {
        "cats": [
          34
        ],
        "implies": "Java"
      },
      "Luigi’s Box": {
        "cats": [
          10,
          29
        ],
        "js": {
          "Luigis": ""
        }
      },
      "M.R. Inc BoxyOS": {
        "cats": [
          28
        ]
      },
      "M.R. Inc SiteFrame": {
        "cats": [
          18
        ],
        "headers": {
          "Powered-By": "M\\.R\\. Inc SiteFrame"
        }
      },
      "M.R. Inc Webserver": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "M\\.R\\. Inc Webserver"
        },
        "implies": [
          "M.R. Inc BoxyOS"
        ]
      },
      "MHonArc": {
        "cats": [
          50
        ],
        "html": "<!-- MHonArc v([0-9.]+) -->\\;version:\\1"
      },
      "MODX": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "^MODX"
        },
        "html": [
          "<a[^>]+>Powered by MODX</a>",
          "<(?:link|script)[^>]+assets/snippets/\\;confidence:20",
          "<form[^>]+id=\"ajaxSearch_form\\;confidence:20",
          "<input[^>]+id=\"ajaxSearch_input\\;confidence:20"
        ],
        "implies": "PHP",
        "js": {
          "MODX": "",
          "MODX_MEDIA_PATH": ""
        },
        "meta": {
          "generator": "MODX[^\\d.]*([\\d.]+)?\\;version:\\1"
        }
      },
      "MYPAGE Platform": {
        "cats": [
          1,
          6
        ],
        "cookies": {
          "mypage_session": ""
        },
        "headers": {
          "CMS-Version": "^(.+)$\\;version:\\1\\;confidence:0"
        },
        "implies": "Laravel"
      },
      "Botble CMS": {
        "cats": [
          1,
          6
        ],
        "cookies": {
          "botble_session": ""
        },
        "headers": {
          "CMS-Version": "^(.+)$\\;version:\\1\\;confidence:0"
        },
        "implies": "Laravel"
      },
      "MadAdsMedia": {
        "cats": [
          36
        ],
        "js": {
          "setMIframe": "",
          "setMRefURL": ""
        },
        "script": "^https?://(?:ads-by|pixel)\\.madadsmedia\\.com/"
      },
      "Magento": {
        "cats": [
          6
        ],
        "cookies": {
          "frontend": "\\;confidence:50"
        },
        "html": [
          "<script [^>]+data-requiremodule=\"mage/\\;version:2",
          "<script [^>]+data-requiremodule=\"Magento_\\;version:2",
          "<script type=\"text/x-magento-init\">"
        ],
        "implies": [
          "PHP",
          "MySQL"
        ],
        "js": {
          "Mage": "",
          "VarienForm": ""
        },
        "script": [
          "js/mage",
          "skin/frontend/(?:default|(enterprise))\\;version:\\1?Enterprise:Community",
          "static/_requirejs\\;confidence:50\\;version:2"
        ]
      },
      "MailChimp": {
        "cats": [
          32
        ],
        "html": [
          "<form [^>]*data-mailchimp-url",
          "<form [^>]*id=\"mc-embedded-subscribe-form\"",
          "<form [^>]*name=\"mc-embedded-subscribe-form\"",
          "<input [^>]*id=\"mc-email\"\\;confidence:20",
          "<!-- Begin MailChimp Signup Form -->"
        ],
        "script": [
          "s3\\.amazonaws\\.com/downloads\\.mailchimp\\.com/js/mc-validate\\.js",
          "cdn-images\\.mailchimp\\.com/[^>]*\\.css"
        ]
      },
      "MakeShopKorea": {
        "cats": [
          6
        ],
        "js": {
          "Makeshop": "",
          "MakeshopLogUniqueId": ""
        }
      },
      "Mambo": {
        "cats": [
          1
        ],
        "excludes": "Joomla",
        "meta": {
          "generator": "Mambo"
        }
      },
      "MantisBT": {
        "cats": [
          13
        ],
        "html": "<img[^>]+ alt=\"Powered by Mantis Bugtracker",
        "implies": "PHP"
      },
      "ManyContacts": {
        "cats": [
          5
        ],
        "script": "\\/assets\\/js\\/manycontacts\\.min\\.js"
      },
      "MariaDB": {
        "cats": [
          34
        ]
      },
      "Marionette.js": {
        "cats": [
          12
        ],
        "implies": [
          "Underscore.js",
          "Backbone.js"
        ],
        "js": {
          "Marionette": "",
          "Marionette.VERSION": "^(.+)$\\;version:\\1"
        },
        "script": "backbone\\.marionette.*\\.js"
      },
      "Marked": {
        "cats": [
          59
        ],
        "js": {
          "marked": ""
        },
        "script": "/marked(?:\\.min)?\\.js"
      },
      "Marketo": {
        "cats": [
          32
        ],
        "js": {
          "Munchkin": ""
        },
        "script": "munchkin\\.marketo\\.net/munchkin\\.js"
      },
      "Material Design Lite": {
        "cats": [
          18
        ],
        "html": "<link[^>]* href=\"[^\"]*material(?:\\.[\\w]+-[\\w]+)?(?:\\.min)?\\.css",
        "js": {
          "MaterialIconToggle": ""
        },
        "script": "(?:/([\\d.]+))?/material(?:\\.min)?\\.js\\;version:\\1"
      },
      "Materialize CSS": {
        "cats": [
          18
        ],
        "html": "<link[^>]* href=\"[^\"]*materialize(?:\\.min)?\\.css",
        "implies": "jQuery",
        "script": "materialize(?:\\.min)?\\.js"
      },
      "MathJax": {
        "cats": [
          25
        ],
        "js": {
          "MathJax": "",
          "MathJax.version": "^(.+)$\\;version:\\1"
        },
        "script": "([\\d.]+)?/mathjax\\.js\\;version:\\1"
      },
      "Matomo": {
        "cats": [
          10
        ],
        "cookies": {
          "PIWIK_SESSID": ""
        },
        "js": {
          "Matomo": "",
          "Piwik": "",
          "_paq": ""
        },
        "meta": {
          "apple-itunes-app": "app-id=737216887",
          "generator": "(?:Matomo|Piwik) - Open Source Web Analytics",
          "google-play-app": "app-id=org\\.piwik\\.mobile2"
        },
        "script": "piwik\\.js|piwik\\.php"
      },
      "Mattermost": {
        "cats": [
          2
        ],
        "html": "<noscript> To use Mattermost, please enable JavaScript\\. </noscript>",
        "implies": [
          "Go",
          "React"
        ],
        "js": {
          "mm_config": "",
          "mm_current_user_id": "",
          "mm_license": "",
          "mm_user": ""
        }
      },
      "Mautic": {
        "cats": [
          32
        ],
        "js": {
          "MauticTrackingObject": ""
        },
        "script": "[^a-z]mtc.*\\.js"
      },
      "MaxCDN": {
        "cats": [
          31
        ],
        "headers": {
          "Server": "^NetDNA",
          "X-CDN-Forward": "^maxcdn$"
        }
      },
      "MaxSite CMS": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "MaxSite CMS"
        }
      },
      "Mean.io": {
        "cats": [
          12
        ],
        "headers": {
          "X-Powered-CMS": "Mean\\.io"
        },
        "implies": [
          "MongoDB",
          "Express",
          "Angular"
        ]
      },
      "MediaElement.js": {
        "cats": [
          14
        ],
        "js": {
          "mejs": "",
          "mejs.version": "^(.+)$\\;version:\\1"
        }
      },
      "MediaTomb": {
        "cats": [
          38
        ],
        "headers": {
          "Server": "MediaTomb(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "MediaWiki": {
        "cats": [
          8
        ],
        "html": [
          "<body[^>]+class=\"mediawiki\"",
          "<(?:a|img)[^>]+>Powered by MediaWiki</a>",
          "<a[^>]+/Special:WhatLinksHere/"
        ],
        "implies": "PHP",
        "js": {
          "mw.util.toggleToc": ""
        },
        "meta": {
          "generator": "^MediaWiki ?(.+)$\\;version:\\1"
        }
      },
      "Medium": {
        "cats": [
          11
        ],
        "headers": {
          "X-Powered-By": "^Medium$"
        },
        "implies": "Node.js",
        "script": "medium\\.com",
        "url": "^https?://(?:www\\.)?medium\\.com"
      },
      "Meebo": {
        "cats": [
          5
        ],
        "html": "(?:<iframe id=\"meebo-iframe\"|Meebo\\('domReady'\\))"
      },
      "Melis CMS V2": {
        "cats": [
          1,
          6
        ],
        "html": "<!-- Rendered with Melis CMS V2",
        "meta": {
          "powered-by": "^Melis CMS"
        }
      },
      "Mermaid": {
        "cats": [
          25
        ],
        "html": "<div [^>]*class=[\"']mermaid[\"']>\\;confidence:90",
        "js": {
          "mermaid": ""
        },
        "script": "/mermaid(?:\\.min)?\\.js"
      },
      "Meteor": {
        "cats": [
          12
        ],
        "html": "<link[^>]+__meteor-css__",
        "implies": [
          "MongoDB",
          "Node.js"
        ],
        "js": {
          "Meteor": "",
          "Meteor.release": "^METEOR@([\\d.]+)\\;version:\\1"
        }
      },
      "Methode": {
        "cats": [
          1
        ],
        "html": "<!-- Methode uuid: \"[a-f\\d]+\" ?-->",
        "meta": {
          "eomportal-id": "\\d+",
          "eomportal-instanceid": "\\d+",
          "eomportal-lastUpdate": "",
          "eomportal-loid": "[\\d.]+",
          "eomportal-uuid": "[a-f\\d]+"
        }
      },
      "Microsoft ASP.NET": {
        "cats": [
          18
        ],
        "cookies": {
          "ASP.NET_SessionId": "",
          "ASPSESSION": ""
        },
        "headers": {
          "X-AspNet-Version": "(.+)\\;version:\\1",
          "X-Powered-By": "^ASP\\.NET"
        },
        "html": "<input[^>]+name=\"__VIEWSTATE",
        "implies": "IIS\\;confidence:50",
        "url": "\\.aspx?(?:$|\\?)"
      },
      "Microsoft Excel": {
        "cats": [
          20
        ],
        "html": "(?:<html [^>]*xmlns:w=\"urn:schemas-microsoft-com:office:excel\"|<!--\\s*(?:START|END) OF OUTPUT FROM EXCEL PUBLISH AS WEB PAGE WIZARD\\s*-->|<div [^>]*x:publishsource=\"?Excel\"?)",
        "meta": {
          "ProgId": "^Excel\\.",
          "generator": "Microsoft Excel( [\\d.]+)?\\;version:\\1"
        }
      },
      "Microsoft HTTPAPI": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Microsoft-HTTPAPI(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "Microsoft PowerPoint": {
        "cats": [
          20
        ],
        "html": "(?:<html [^>]*xmlns:w=\"urn:schemas-microsoft-com:office:powerpoint\"|<link rel=\"?Presentation-XML\"? href=\"?[^\"]+\\.xml\"?>|<o:PresentationFormat>[^<]+</o:PresentationFormat>[^!]+<o:Slides>\\d+</o:Slides>(?:[^!]+<o:Version>([\\d.]+)</o:Version>)?)\\;version:\\1",
        "meta": {
          "ProgId": "^PowerPoint\\.",
          "generator": "Microsoft PowerPoint ( [\\d.]+)?\\;version:\\1"
        }
      },
      "Microsoft Publisher": {
        "cats": [
          20
        ],
        "html": "(?:<html [^>]*xmlns:w=\"urn:schemas-microsoft-com:office:publisher\"|<!--[if pub]><xml>)",
        "meta": {
          "ProgId": "^Publisher\\.",
          "generator": "Microsoft Publisher( [\\d.]+)?\\;version:\\1"
        }
      },
      "Microsoft SharePoint": {
        "cats": [
          1
        ],
        "headers": {
          "MicrosoftSharePointTeamServices": "^(.+)$\\;version:\\1",
          "SPRequestGuid": "",
          "SharePointHealthScore": "",
          "X-SharePointHealthScore": ""
        },
        "js": {
          "SPDesignerProgID": "",
          "_spBodyOnLoadCalled": ""
        },
        "meta": {
          "generator": "Microsoft SharePoint"
        }
      },
      "Microsoft Word": {
        "cats": [
          20
        ],
        "html": "(?:<html [^>]*xmlns:w=\"urn:schemas-microsoft-com:office:word\"|<w:WordDocument>|<div [^>]*class=\"?WordSection1[\" >]|<style[^>]*>[^>]*@page WordSection1)",
        "meta": {
          "ProgId": "^Word\\.",
          "generator": "Microsoft Word( [\\d.]+)?\\;version:\\1"
        }
      },
      "Mietshop": {
        "cats": [
          6
        ],
        "html": "<a href=\"https://ssl\\.mietshop\\.d",
        "meta": {
          "generator": "Mietshop"
        }
      },
      "Milligram": {
        "cats": [
          18
        ],
        "html": [
          "<link[^>]+?href=\"[^\"]+milligram(?:\\.min)?\\.css"
        ]
      },
      "Minero.cc": {
        "cats": [
          56
        ],
        "script": [
          "//minero\\.cc/lib/minero(?:-miner|-hidden)?\\.min\\.js"
        ]
      },
      "MiniBB": {
        "cats": [
          2
        ],
        "html": "<a href=\"[^\"]+minibb[^<]+</a>[^<]+\\n<!--End of copyright link"
      },
      "MiniServ": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "MiniServ\\/?([\\d\\.]+)?\\;version:\\1"
        }
      },
      "Mint": {
        "cats": [
          10
        ],
        "js": {
          "Mint": ""
        },
        "script": "mint/\\?js"
      },
      "Mithril": {
        "cats": [
          12
        ],
        "script": "mithril/\\?js"
      },
      "Mixpanel": {
        "cats": [
          10
        ],
        "js": {
          "mixpanel": ""
        },
        "script": "api\\.mixpanel\\.com/track"
      },
      "MkDocs": {
        "cats": [
          4
        ],
        "meta": {
          "generator": "^mkdocs-([\\d.]+)\\;version:\\1"
        }
      },
      "Mobify": {
        "cats": [
          26
        ],
        "js": {
          "Mobify": ""
        },
        "script": "//cdn\\.mobify\\.com/"
      },
      "Mobirise": {
        "cats": [
          51
        ],
        "html": [
          "<!-- Site made with Mobirise Website Builder v([\\d.]+)\\;version:\\1"
        ],
        "meta": {
          "generator": "^Mobirise v([\\d.]+)\\;version:\\1"
        }
      },
      "MochiKit": {
        "cats": [
          59
        ],
        "js": {
          "MochiKit": "",
          "MochiKit.MochiKit.VERSION": "^(.+)$\\;version:\\1"
        },
        "script": "MochiKit(?:\\.min)?\\.js"
      },
      "MochiWeb": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "MochiWeb(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "Modernizr": {
        "cats": [
          59
        ],
        "js": {
          "Modernizr._version": "^(.+)$\\;version:\\1"
        },
        "script": [
          "([\\d.]+)?/modernizr(?:.([\\d.]+))?.*\\.js\\;version:\\1?\\1:\\2"
        ]
      },
      "Modified": {
        "cats": [
          6
        ],
        "meta": {
          "generator": "\\(c\\) by modified eCommerce Shopsoftware ------ http://www\\.modified-shop\\.org"
        }
      },
      "Moguta.CMS": {
        "cats": [
          1,
          6
        ],
        "html": "<link[^>]+href=[\"'][^\"]+mg-(?:core|plugins|templates)/",
        "script": "mg-(?:core|plugins|templates)/",
        "implies": "PHP"
      },
      "MoinMoin": {
        "cats": [
          8
        ],
        "cookies": {
          "MOIN_SESSION": ""
        },
        "implies": "Python",
        "js": {
          "show_switch2gui": ""
        },
        "script": "moin(?:_static(\\d)(\\d)(\\d)|.+)/common/js/common\\.js\\;version:\\1.\\2.\\3"
      },
      "Mojolicious": {
        "cats": [
          18
        ],
        "headers": {
          "server": "^mojolicious",
          "x-powered-by": "mojolicious"
        },
        "implies": "Perl"
      },
      "Mollom": {
        "cats": [
          16
        ],
        "html": "<img[^>]+\\.mollom\\.com",
        "script": "mollom(?:\\.min)?\\.js"
      },
      "Moment Timezone": {
        "cats": [
          59
        ],
        "implies": "Moment.js",
        "script": "moment-timezone(?:-data)?(?:\\.min)?\\.js"
      },
      "Moment.js": {
        "cats": [
          59
        ],
        "js": {
          "moment": "",
          "moment.version": "^(.+)$\\;version:\\1"
        },
        "script": "moment(?:\\.min)?\\.js"
      },
      "Mondo Media": {
        "cats": [
          6
        ],
        "meta": {
          "generator": "Mondo Shop"
        }
      },
      "Monerominer": {
        "cats": [
          56
        ],
        "html": "<iframe[^>]+src=[\\'\"]https?://monerominer\\.rocks/miner\\.php\\?siteid="
      },
      "MongoDB": {
        "cats": [
          34
        ]
      },
      "Mongrel": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Mongrel"
        },
        "implies": "Ruby"
      },
      "Monkey HTTP Server": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Monkey/?([\\d.]+)?\\;version:\\1"
        }
      },
      "Mono": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "Mono"
        }
      },
      "Mono.net": {
        "cats": [
          1
        ],
        "implies": "Matomo",
        "js": {
          "_monoTracker": ""
        },
        "script": "monotracker(?:\\.min)?\\.js"
      },
      "MooTools": {
        "cats": [
          12
        ],
        "js": {
          "MooTools": "",
          "MooTools.version": "^(.+)$\\;version:\\1"
        },
        "script": "mootools.*\\.js"
      },
      "Moodle": {
        "cats": [
          21
        ],
        "cookies": {
          "MOODLEID_": "",
          "MoodleSession": ""
        },
        "html": "<img[^>]+moodlelogo",
        "implies": "PHP",
        "js": {
          "M.core": "",
          "Y.Moodle": ""
        },
        "meta": {
          "keywords": "^moodle"
        }
      },
      "Moon": {
        "cats": [
          12
        ],
        "script": "/moon(?:\\.min)?\\.js$"
      },
      "MotoCMS": {
        "cats": [
          1
        ],
        "html": "<link [^>]*href=\"[^>]*\\/mt-content\\/[^>]*\\.css",
        "implies": [
          "PHP",
          "AngularJS",
          "jQuery"
        ],
        "script": "/mt-includes/js/website(?:assets)?\\.(?:min)?\\.js"
      },
      "Mouse Flow": {
        "cats": [
          10
        ],
        "js": {
          "_mfq": ""
        },
        "script": [
          "cdn\\.mouseflow\\.com"
        ]
      },
      "Movable Type": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "Movable Type"
        }
      },
      "Mozard Suite": {
        "cats": [
          1
        ],
        "meta": {
          "author": "Mozard"
        },
        "url": "/mozard/!suite"
      },
      "Mura CMS": {
        "cats": [
          1,
          11
        ],
        "implies": "Adobe ColdFusion",
        "meta": {
          "generator": "Mura CMS ([\\d]+)\\;version:\\1"
        }
      },
      "Mustache": {
        "cats": [
          12
        ],
        "js": {
          "Mustache.version": "^(.+)$\\;version:\\1"
        },
        "script": "mustache(?:\\.min)?\\.js"
      },
      "MyBB": {
        "cats": [
          2
        ],
        "html": "(?:<script [^>]+\\s+<!--\\s+lang\\.no_new_posts|<a[^>]* title=\"Powered By MyBB)",
        "implies": [
          "PHP",
          "MySQL"
        ],
        "js": {
          "MyBB": ""
        }
      },
      "MyBlogLog": {
        "cats": [
          5
        ],
        "script": "pub\\.mybloglog\\.com"
      },
      "MySQL": {
        "cats": [
          34
        ]
      },
      "Mynetcap": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "Mynetcap"
        }
      },
      "NEO - Omnichannel Commerce Platform": {
        "cats": [
          6
        ],
        "headers": {
          "powered": "jet-neo"
        }
      },
      "NVD3": {
        "cats": [
          25
        ],
        "html": "<link[^>]* href=[^>]+nv\\.d3(?:\\.min)?\\.css",
        "implies": "D3",
        "js": {
          "nv.addGraph": "",
          "nv.version": "^(.+)$\\;confidence:0\\;version:\\1"
        },
        "script": "nv\\.d3(?:\\.min)?\\.js"
      },
      "Navegg": {
        "cats": [
          10
        ],
        "script": "tag\\.navdmp\\.com"
      },
      "Neos CMS": {
        "cats": [
          1
        ],
        "excludes": "TYPO3 CMS",
        "headers": {
          "X-Flow-Powered": "Neos/?(.+)?$\\;version:\\1"
        },
        "implies": "Neos Flow",
        "url": "/neos/"
      },
      "Neos Flow": {
        "cats": [
          18
        ],
        "excludes": "TYPO3 CMS",
        "headers": {
          "X-Flow-Powered": "Flow/?(.+)?$\\;version:\\1"
        },
        "implies": "PHP"
      },
      "Nepso": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-CMS": "Nepso"
        }
      },
      "Netlify": {
        "cats": [
          22,
          31
        ],
        "headers": {
          "X-NF-Request-ID": "",
          "Server": "^Netlify"
        }
      },
      "Neto": {
        "cats": [
          6
        ],
        "js": {
          "NETO": ""
        },
        "script": "jquery\\.neto.*\\.js"
      },
      "Netsuite": {
        "cats": [
          6
        ],
        "cookies": {
          "NS_VER": ""
        }
      },
      "Nette Framework": {
        "cats": [
          18
        ],
        "cookies": {
          "nette-browser": ""
        },
        "headers": {
          "X-Powered-By": "^Nette Framework"
        },
        "html": [
          "<input[^>]+data-nette-rules",
          "<div[^>]+id=\"snippet-",
          "<input[^>]+id=\"frm-"
        ],
        "implies": "PHP",
        "js": {
          "Nette": "",
          "Nette.version": "^(.+)$\\;version:\\1"
        }
      },
      "New Relic": {
        "cats": [
          10
        ],
        "js": {
          "NREUM": "",
          "newrelic": ""
        }
      },
      "Next.js": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "x-powered-by": "^Next\\.js ?([0-9.]+)?\\;version:\\1"
        },
        "implies": [
          "React",
          "webpack",
          "Node.js"
        ],
        "js": {
          "__NEXT_DATA__": ""
        }
      },
      "NextGEN Gallery": {
        "cats": [
          7
        ],
        "html": [
          "<!-- <meta name=\"NextGEN\" version=\"([\\d.]+)\" /> -->\\;version:\\1"
        ],
        "implies": [
          "WordPress"
        ],
        "script": "/nextgen-gallery/js/"
      },
      "Nginx": {
        "cats": [
          22,
          64
        ],
        "headers": {
          "Server": "nginx(?:/([\\d.]+))?\\;version:\\1",
          "X-Fastcgi-Cache": ""
        }
      },
      "Node.js": {
        "cats": [
          27
        ]
      },
      "NodeBB": {
        "cats": [
          2
        ],
        "headers": {
          "X-Powered-By": "^NodeBB$"
        },
        "implies": "Node.js",
        "script": "^/nodebb\\.min\\.js\\?"
      },
      "Now": {
        "cats": [
          22
        ],
        "headers": {
          "server": "^now$",
          "x-now-trace": "",
          "x-now-id": "",
          "x-now-cache": ""
        }
      },
      "OWL Carousel": {
        "cats": [
          5
        ],
        "html": "<link [^>]*href=\"[^\"]+owl\\.carousel(?:\\.min)?\\.css",
        "implies": "jQuery",
        "script": "owl\\.carousel.*\\.js"
      },
      "OXID eShop": {
        "cats": [
          6
        ],
        "html": "<!--[^-]*OXID eShop",
        "js": {
          "oxCookieNote": "",
          "oxInputValidator": "",
          "oxLoginBox": "",
          "oxModalPopup": "",
          "oxTopMenu": ""
        }
      },
      "October CMS": {
        "cats": [
          1
        ],
        "cookies": {
          "october_session=": ""
        },
        "implies": "Laravel"
      },
      "Octopress": {
        "cats": [
          57
        ],
        "html": "Powered by <a href=\"http://octopress\\.org\">",
        "implies": "Jekyll",
        "meta": {
          "generator": "Octopress"
        },
        "script": "/octopress\\.js"
      },
      "Odoo": {
        "cats": [
          1,
          6
        ],
        "html": "<link[^>]* href=[^>]+/web/css/(?:web\\.assets_common/|website\\.assets_frontend/)\\;confidence:25",
        "implies": [
          "Python",
          "PostgreSQL",
          "Node.js",
          "Less"
        ],
        "meta": {
          "generator": "Odoo"
        },
        "script": "/web/js/(?:web\\.assets_common/|website\\.assets_frontend/)\\;confidence:25"
      },
      "Olark": {
        "cats": [
          52
        ],
        "script": "^https?:\\/\\/static\\.olark\\.com\\/jsclient\\/loader1\\.js"
      },
      "OneAPM": {
        "cats": [
          10
        ],
        "js": {
          "BWEUM": ""
        }
      },
      "OneStat": {
        "cats": [
          10
        ],
        "js": {
          "OneStat_Pageview": ""
        }
      },
      "Open AdStream": {
        "cats": [
          36
        ],
        "js": {
          "OAS_AD": ""
        }
      },
      "Open Classifieds": {
        "cats": [
          6
        ],
        "meta": {
          "author": "open-classifieds\\.com",
          "copyright": "Open Classifieds ?([0-9.]+)?\\;version:\\1"
        }
      },
      "Open Journal Systems": {
        "cats": [
          50
        ],
        "cookies": {
          "OJSSID": ""
        },
        "implies": "PHP",
        "meta": {
          "generator": "Open Journal Systems(?: ([\\d.]+))?\\;version:\\1"
        }
      },
      "Open Web Analytics": {
        "cats": [
          10
        ],
        "html": "<!-- (?:Start|End) Open Web Analytics Tracker -->",
        "js": {
          "OWA.config.baseUrl": "",
          "owa_baseUrl": "",
          "owa_cmds": ""
        }
      },
      "Open eShop": {
        "cats": [
          6
        ],
        "implies": "PHP",
        "meta": {
          "author": "open-eshop\\.com",
          "copyright": "Open eShop ?([0-9.]+)?\\;version:\\1"
        }
      },
      "OpenCart": {
        "cats": [
          6
        ],
        "cookies": {
          "OCSESSID": ""
        },
        "implies": "PHP"
      },
      "OpenCms": {
        "cats": [
          1
        ],
        "headers": {
          "Server": "OpenCms"
        },
        "html": "<link href=\"/opencms/",
        "implies": "Java",
        "script": "opencms"
      },
      "OpenGSE": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "GSE"
        },
        "implies": "Java"
      },
      "OpenGrok": {
        "cats": [
          19
        ],
        "cookies": {
          "OpenGrok": ""
        },
        "implies": "Java",
        "meta": {
          "generator": "OpenGrok(?: v?([\\d.]+))?\\;version:\\1"
        }
      },
      "OpenLayers": {
        "cats": [
          35
        ],
        "js": {
          "OpenLayers.VERSION_NUMBER": "([\\d.]+)\\;version:\\1",
          "ol.CanvasMap": ""
        },
        "script": "openlayers"
      },
      "OpenNemas": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "OpenNemas"
        },
        "meta": {
          "generator": "OpenNemas"
        }
      },
      "OpenResty": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "openresty(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": [
          "Nginx",
          "Lua"
        ]
      },
      "OpenSSL": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "OpenSSL(?:/([\\d.]+[a-z]?))?\\;version:\\1"
        }
      },
      "OpenText Web Solutions": {
        "cats": [
          1
        ],
        "html": "<!--[^>]+published by Open Text Web Solutions",
        "implies": "Microsoft ASP.NET"
      },
      "OpenUI5": {
        "cats": [
          12
        ],
        "js": {
          "sap.ui.version": "^(.+)$\\;version:\\1"
        },
        "script": "sap-ui-core\\.js"
      },
      "OpenX": {
        "cats": [
          36
        ],
        "script": [
          "https?://[^/]*\\.openx\\.net",
          "https?://[^/]*\\.servedbyopenx\\.com"
        ]
      },
      "Ophal": {
        "cats": [
          1,
          11,
          18
        ],
        "headers": {
          "X-Powered-By": "Ophal(?: (.+))? \\(ophal\\.org\\)\\;version:\\1"
        },
        "implies": "Lua",
        "meta": {
          "generator": "Ophal(?: (.+))? \\(ophal\\.org\\)\\;version:\\1"
        },
        "script": "ophal\\.js"
      },
      "Optimizely": {
        "cats": [
          10
        ],
        "js": {
          "optimizely": ""
        },
        "script": "optimizely\\.com.*\\.js"
      },
      "Oracle Application Server": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Oracle[- ]Application[- ]Server(?: Containers for J2EE)?(?:[- ](\\d[\\da-z./]+))?\\;version:\\1"
        }
      },
      "Oracle Commerce": {
        "cats": [
          6
        ],
        "headers": {
          "X-ATG-Version": "(?:ATGPlatform/([\\d.]+))?\\;version:\\1"
        },
        "html": "<[^>]+_dyncharset"
      },
      "Oracle Commerce Cloud": {
        "cats": [
          6
        ],
        "headers": {
          "OracleCommerceCloud-Version": "^(.+)$\\;version:\\1"
        },
        "html": "<[^>]+id=\"oracle-cc\""
      },
      "Oracle Dynamic Monitoring Service": {
        "cats": [
          19
        ],
        "headers": {
          "x-oracle-dms-ecid": ""
        }
      },
      "Oracle HTTP Server": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Oracle-HTTP-Server(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "Oracle Recommendations On Demand": {
        "cats": [
          10
        ],
        "script": "atgsvcs.+atgsvcs\\.js"
      },
      "Oracle Web Cache": {
        "cats": [
          23
        ],
        "headers": {
          "Server": "Oracle(?:AS)?[- ]Web[- ]Cache(?:[- /]([\\da-z./]+))?\\;version:\\1"
        }
      },
      "Orchard CMS": {
        "cats": [
          1
        ],
        "implies": "Microsoft ASP.NET",
        "meta": {
          "generator": "Orchard"
        }
      },
      "Outbrain": {
        "cats": [
          5
        ],
        "js": {
          "OB_releaseVer": "^(.+)$\\;version:\\1",
          "OutbrainPermaLink": ""
        },
        "script": "widgets\\.outbrain\\.com/outbrain\\.js"
      },
      "Outlook Web App": {
        "cats": [
          30
        ],
        "html": "<link\\s[^>]*href=\"[^\"]*?([\\d.]+)/themes/resources/owafont\\.css\\;version:\\1",
        "implies": "Microsoft ASP.NET",
        "js": {
          "IsOwaPremiumBrowser": ""
        },
        "url": "/owa/auth/log(?:on|off)\\.aspx"
      },
      "PANSITE": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "PANSITE"
        }
      },
      "PDF.js": {
        "cats": [
          19
        ],
        "html": "<\\/div>\\s*<!-- outerContainer -->\\s*<div\\s*id=\"printContainer\"><\\/div>",
        "js": {
          "PDFJS": "",
          "PDFJS.version": "^(.+)$\\;version:\\1"
        },
        "url": "/web/viewer\\.html?file=[^&]\\.pdf"
      },
      "PHP": {
        "cats": [
          27
        ],
        "cookies": {
          "PHPSESSID": ""
        },
        "headers": {
          "Server": "php/?([\\d.]+)?\\;version:\\1",
          "X-Powered-By": "^php/?([\\d.]+)?\\;version:\\1"
        },
        "url": "\\.php(?:$|\\?)"
      },
      "PHP-Fusion": {
        "cats": [
          1
        ],
        "html": "Powered by <a href=\"[^>]+php-fusion",
        "headers": {
          "X-Powered-By": "PHP-Fusion (.+)$\\;version:\\1"
        },
        "implies": [
          "PHP",
          "MySQL"
        ]
      },
      "PHP-Nuke": {
        "cats": [
          1
        ],
        "html": "<[^>]+Powered by PHP-Nuke",
        "implies": "PHP",
        "meta": {
          "generator": "PHP-Nuke"
        }
      },
      "PHPDebugBar": {
        "cats": [
          47
        ],
        "js": {
          "PhpDebugBar": "",
          "phpdebugbar": ""
        },
        "script": [
          "debugbar.*\\.js"
        ]
      },
      "Cecil": {
        "cats": [
          57
        ],
        "meta": {
          "generator": "^Cecil|PHPoole$"
        }
      },
      "Pagekit": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "Pagekit"
        }
      },
      "Pagevamp": {
        "cats": [
          1
        ],
        "headers": {
          "X-ServedBy": "pagevamp"
        },
        "js": {
          "Pagevamp": ""
        }
      },
      "Pantheon": {
        "cats": [
          62
        ],
        "headers": {
          "x-pantheon-styx-hostname": "",
          "Server": "^Pantheon"
        },
        "implies": [
          "PHP",
          "Nginx",
          "MariaDB"
        ]
      },
      "Paper.js": {
        "cats": [
          25
        ],
        "js": {
          "paper.version": "^(.+)$\\;version:\\1"
        }
      },
      "Pardot": {
        "cats": [
          32
        ],
        "headers": {
          "X-Pardot-LB": "",
          "X-Pardot-Route": "",
          "X-Pardot-Rsp": ""
        },
        "js": {
          "piAId": "",
          "piCId": "",
          "piHostname": "",
          "piProtocol": "",
          "piTracker": ""
        }
      },
      "Pars Elecom Portal": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "Pars Elecom Portal"
        },
        "implies": [
          "Microsoft ASP.NET",
          "IIS",
          "Windows Server"
        ],
        "meta": {
          "copyright": "Pars Elecom Portal"
        }
      },
      "Parse.ly": {
        "cats": [
          10
        ],
        "js": {
          "PARSELY": ""
        }
      },
      "Paths.js": {
        "cats": [
          25
        ],
        "script": "paths(?:\\.min)?\\.js"
      },
      "PayPal": {
        "cats": [
          41
        ],
        "html": "<input[^>]+_s-xclick",
        "js": {
          "PAYPAL": ""
        },
        "script": "paypalobjects\\.com/js"
      },
      "Pelican": {
        "cats": [
          57
        ],
        "html": [
          "powered by <a href=\"[^>]+getpelican\\.com",
          "powered by <a href=\"https?://pelican\\.notmyidea\\.org"
        ],
        "implies": "Python"
      },
      "PencilBlue": {
        "cats": [
          1,
          11
        ],
        "headers": {
          "X-Powered-By": "PencilBlue"
        },
        "implies": "Node.js"
      },
      "Pendo": {
        "cats": [
          58
        ],
        "script": "cdn\\.pendo\\.io*\\.js"
      },
      "Percona": {
        "cats": [
          34
        ]
      },
      "Percussion": {
        "cats": [
          1
        ],
        "html": "<[^>]+class=\"perc-region\"",
        "meta": {
          "generator": "(?:Percussion|Rhythmyx)"
        }
      },
      "Perl": {
        "cats": [
          27
        ],
        "headers": {
          "Server": "\\bPerl\\b(?: ?/?v?([\\d.]+))?\\;version:\\1"
        }
      },
      "Phabricator": {
        "cats": [
          13,
          47
        ],
        "cookies": {
          "phsid": ""
        },
        "html": "<[^>]+(?:class|id)=\"phabricator-",
        "implies": [
          "PHP"
        ],
        "script": "/phabricator/[a-f0-9]{8}/rsrc/js/phui/[a-z-]+\\.js$"
      },
      "Phaser": {
        "cats": [
          12
        ],
        "js": {
          "Phaser": "",
          "Phaser.VERSION": "^(.+)$\\;version:\\1"
        }
      },
      "Phenomic": {
        "cats": [
          57
        ],
        "html": [
          "<[^>]+id=\"phenomic(?:root)?\""
        ],
        "implies": [
          "React"
        ],
        "script": "/phenomic\\.browser\\.[a-f0-9]+\\.js"
      },
      "Phusion Passenger": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Phusion Passenger ([\\d.]+)\\;version:\\1",
          "X-Powered-By": "Phusion Passenger ?([\\d.]+)?\\;version:\\1"
        }
      },
      "Pimcore": {
        "cats": [
          1,
          6,
          18
        ],
        "headers": {
          "X-Powered-By": "^pimcore$"
        },
        "implies": "PHP"
      },
      "Pinterest": {
        "cats": [
          5
        ],
        "script": "//assets\\.pinterest\\.com/js/pinit\\.js"
      },
      "Planet": {
        "cats": [
          49
        ],
        "meta": {
          "generator": "^Planet(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "PlatformOS": {
        "cats": [
          1,
          62
        ],
        "headers": {
          "x-powered-by": "^platformOS$"
        }
      },
      "Platform.sh": {
        "cats": [
          62
        ],
        "headers": {
          "x-platform-cluster": "",
          "x-platform-processor": "",
          "x-platform-router": "",
          "x-platform-server": ""
        }
      },
      "Play": {
        "cats": [
          18
        ],
        "cookies": {
          "PLAY_SESSION": ""
        },
        "implies": "Scala"
      },
      "Plentymarkets": {
        "cats": [
          6
        ],
        "meta": {
          "generator": "plentymarkets"
        }
      },
      "Plesk": {
        "cats": [
          9
        ],
        "headers": {
          "X-Powered-By": "^Plesk(?:L|W)in",
          "X-Powered-By-Plesk": "^Plesk"
        },
        "script": "common\\.js\\?plesk"
      },
      "Pligg": {
        "cats": [
          1
        ],
        "html": "<span[^>]+id=\"xvotes-0",
        "js": {
          "pligg_": ""
        },
        "meta": {
          "generator": "Pligg"
        }
      },
      "Plone": {
        "cats": [
          1
        ],
        "implies": "Python",
        "meta": {
          "generator": "Plone"
        }
      },
      "Plotly": {
        "cats": [
          25
        ],
        "implies": "D3",
        "js": {
          "Plotly.version": "([\\d.])\\;version:\\1"
        },
        "script": "https?://cdn\\.plot\\.ly/plotly"
      },
      "Po.st": {
        "cats": [
          5
        ],
        "js": {
          "pwidget_config": ""
        }
      },
      "Polyfill": {
        "cats": [
          59
        ],
        "script": [
          "^https?://cdn\\.polyfill\\.io/",
          "/polyfill\\.min\\.js"
        ]
      },
      "Polymer": {
        "cats": [
          12
        ],
        "html": "(?:<polymer-[^>]+|<link[^>]+rel=\"import\"[^>]+/polymer\\.html\")",
        "js": {
          "Polymer.version": "^(.+)$\\;version:\\1"
        },
        "script": "polymer\\.js"
      },
      "Posterous": {
        "cats": [
          1,
          11
        ],
        "html": "<div class=\"posterous",
        "js": {
          "Posterous": ""
        }
      },
      "PostgreSQL": {
        "cats": [
          34
        ]
      },
      "Powergap": {
        "cats": [
          6
        ],
        "html": [
          "<a[^>]+title=\"POWERGAP",
          "<input type=\"hidden\" name=\"shopid\""
        ]
      },
      "Prebid": {
        "cats": [
          36
        ],
        "js": {
          "PREBID_TIMEOUT": "",
          "pbjs": ""
        },
        "script": [
          "/prebid\\.js",
          "adnxs\\.com/[^\"]*(?:prebid|/pb\\.js)"
        ]
      },
      "Prefix-Free": {
        "cats": [
          19
        ],
        "js": {
          "PrefixFree": ""
        },
        "script": "prefixfree\\.js"
      },
      "PrestaShop": {
        "cats": [
          6
        ],
        "cookies": {
          "PrestaShop": ""
        },
        "headers": {
          "Powered-By": "^Prestashop$"
        },
        "html": [
          "Powered by <a\\s+[^>]+>PrestaShop",
          "<!-- /Block [a-z ]+ module (?:HEADER|TOP)?\\s?-->",
          "<!-- /Module Block [a-z ]+ -->"
        ],
        "implies": [
          "PHP",
          "MySQL"
        ],
        "js": {
          "freeProductTranslation": "\\;confidence:25",
          "priceDisplayMethod": "\\;confidence:25",
          "priceDisplayPrecision": "\\;confidence:25"
        },
        "meta": {
          "generator": "PrestaShop"
        }
      },
      "Prism": {
        "cats": [
          19
        ],
        "js": {
          "Prism": ""
        },
        "script": "prism\\.js"
      },
      "Project Wonderful": {
        "cats": [
          36
        ],
        "html": "<div[^>]+id=\"pw_adbox_",
        "js": {
          "pw_adloader": ""
        },
        "script": "^https?://(?:www\\.)?projectwonderful\\.com/(?:pwa\\.js|gen\\.php)"
      },
      "ProjectPoi": {
        "cats": [
          56
        ],
        "js": {
          "ProjectPoi": ""
        },
        "script": "^(?:https):?//ppoi\\.org/lib/"
      },
      "Projesoft": {
        "cats": [
          6
        ],
        "script": [
          "projesoft\\.js"
        ]
      },
      "Prototype": {
        "cats": [
          12
        ],
        "js": {
          "Prototype.Version": "^(.+)$\\;version:\\1"
        },
        "script": "(?:prototype|protoaculous)(?:-([\\d.]*[\\d]))?.*\\.js\\;version:\\1"
      },
      "Protovis": {
        "cats": [
          25
        ],
        "js": {
          "protovis": ""
        },
        "script": "protovis.*\\.js"
      },
      "Proximis Omnichannel": {
        "cats": [
          6,
          1
        ],
        "html": "<html[^>]+data-ng-app=\"RbsChangeApp\"",
        "implies": [
          "PHP",
          "AngularJS"
        ],
        "js": {
          "__change": ""
        },
        "meta": {
          "generator": "Proximis Omnichannel"
        }
      },
      "Proximis Web to Store": {
        "cats": [
          5,
          6
        ],
        "script": "widget-commerce(?:\\.min)?\\.js"
      },
      "PubMatic": {
        "cats": [
          36
        ],
        "script": "https?://[^/]*\\.pubmatic\\.com"
      },
      "Public CMS": {
        "cats": [
          1
        ],
        "cookies": {
          "PUBLICCMS_USER": ""
        },
        "headers": {
          "X-Powered-PublicCMS": "^(.+)$\\;version:\\1"
        },
        "implies": "Java"
      },
      "Pure CSS": {
        "cats": [
          18
        ],
        "html": [
          "<link[^>]+(?:([\\d.])+/)?pure(?:-min)?\\.css\\;version:\\1",
          "<div[^>]+class=\"[^\"]*pure-u-(?:sm-|md-|lg-|xl-)?\\d-\\d"
        ]
      },
      "Pygments": {
        "cats": [
          19
        ],
        "html": "<link[^>]+pygments\\.css[\"']"
      },
      "PyroCMS": {
        "cats": [
          1
        ],
        "cookies": {
          "pyrocms": ""
        },
        "headers": {
          "X-Streams-Distribution": "PyroCMS"
        },
        "implies": "Laravel"
      },
      "Python": {
        "cats": [
          27
        ],
        "headers": {
          "Server": "(?:^|\\s)Python(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "Quantcast": {
        "cats": [
          10
        ],
        "js": {
          "quantserve": ""
        },
        "script": "\\.quantserve\\.com/quant\\.js"
      },
      "Question2Answer": {
        "cats": [
          15
        ],
        "html": "<!-- Powered by Question2Answer",
        "implies": "PHP",
        "script": "\\./qa-content/qa-page\\.js\\?([0-9.]+)\\;version:\\1"
      },
      "Quick.CMS": {
        "cats": [
          1
        ],
        "html": "<a href=\"[^>]+opensolution\\.org/\">CMS by",
        "meta": {
          "generator": "Quick\\.CMS(?: v([\\d.]+))?\\;version:\\1"
        }
      },
      "Quick.Cart": {
        "cats": [
          6
        ],
        "html": "<a href=\"[^>]+opensolution\\.org/\">(?:Shopping cart by|Sklep internetowy)",
        "meta": {
          "generator": "Quick\\.Cart(?: v([\\d.]+))?\\;version:\\1"
        }
      },
      "Quill": {
        "cats": [
          24
        ],
        "js": {
          "Quill": ""
        }
      },
      "RBS Change": {
        "cats": [
          1,
          6
        ],
        "html": "<html[^>]+xmlns:change=",
        "implies": "PHP",
        "meta": {
          "generator": "RBS Change"
        }
      },
      "RCMS": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "^(?:RCMS|ReallyCMS)"
        }
      },
      "RD Station": {
        "cats": [
          32
        ],
        "js": {
          "RDStation": ""
        },
        "script": "d335luupugsy2\\.cloudfront\\.net/js/loader-scripts/.*-loader\\.js"
      },
      "RDoc": {
        "cats": [
          4
        ],
        "html": [
          "<link[^>]+href=\"[^\"]*rdoc-style\\.css",
          "Generated by <a[^>]+href=\"https?://rdoc\\.rubyforge\\.org[^>]+>RDoc</a> ([\\d.]*\\d)\\;version:\\1"
        ],
        "implies": "Ruby"
      },
      "RackCache": {
        "cats": [
          23
        ],
        "headers": {
          "X-Rack-Cache": ""
        },
        "implies": "Ruby"
      },
      "RainLoop": {
        "cats": [
          30
        ],
        "headers": {
          "Server": "^RainLoop"
        },
        "html": [
          "<link[^>]href=\"rainloop/v/([0-9.]+)/static/apple-touch-icon\\.png/>\\;version:\\1"
        ],
        "meta": {
          "rlAppVersion": "^([0-9.]+)$\\;version:\\1"
        },
        "implies": "PHP",
        "js": {
          "rainloopI18N": "",
          "rainloop": ""
        },
        "script": "^rainloop/v/([0-9.]+)/\\;version:\\1"
      },
      "Rakuten DBCore": {
        "cats": [
          6
        ],
        "meta": {
          "generator": "Rakuten DBCore",
          "generator:site": "http://ecservice\\.rakuten\\.com\\.br"
        }
      },
      "Rakuten Digital Commerce": {
        "cats": [
          6
        ],
        "js": {
          "RakutenApplication": ""
        }
      },
      "Ramda": {
        "cats": [
          59
        ],
        "script": "ramda.*\\.js"
      },
      "Raphael": {
        "cats": [
          25
        ],
        "js": {
          "Raphael.version": "^(.+)$\\;version:\\1"
        },
        "script": "raphael(?:-([\\d.]+))?(?:\\.min)?\\.js\\;version:\\1"
      },
      "Raspbian": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "Raspbian",
          "X-Powered-By": "Raspbian"
        }
      },
      "Raychat": {
        "cats": [
          52
        ],
        "js": {
          "Raychat": ""
        },
        "script": "app\\.raychat\\.io/scripts/js"
      },
      "Rayo": {
        "cats": [
          1
        ],
        "implies": [
          "AngularJS",
          "Microsoft ASP.NET"
        ],
        "js": {
          "Rayo": ""
        },
        "meta": {
          "generator": "^Rayo"
        }
      },
      "Rdf": {
        "cats": [
          27
        ]
      },
      "ReDoc": {
        "cats": [
          4
        ],
        "html": "<redoc ",
        "implies": "React",
        "js": {
          "Redoc.version": "^(.+)$\\;version:\\1"
        },
        "script": "/redoc\\.(?:min\\.)?js"
      },
      "React": {
        "cats": [
          12
        ],
        "html": "<[^>]+data-react",
        "js": {
          "React.version": "^(.+)$\\;version:\\1",
          "react.version": "^(.+)$\\;version:\\1"
        },
        "script": [
          "react(?:-with-addons)?[.-]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "/([\\d.]+)/react(?:\\.min)?\\.js\\;version:\\1",
          "react.*\\.js"
        ]
      },
      "Red Hat": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "Red Hat",
          "X-Powered-By": "Red Hat"
        }
      },
      "Reddit": {
        "cats": [
          2
        ],
        "html": "(?:<a[^>]+Powered by Reddit|powered by <a[^>]+>reddit<)",
        "implies": "Python",
        "js": {
          "reddit": ""
        },
        "url": "^https?://(?:www\\.)?reddit\\.com"
      },
      "Redmine": {
        "cats": [
          13
        ],
        "cookies": {
          "_redmine_session": ""
        },
        "html": "Powered by <a href=\"[^>]+Redmine",
        "implies": "Ruby on Rails",
        "meta": {
          "description": "Redmine"
        }
      },
      "Reinvigorate": {
        "cats": [
          10
        ],
        "js": {
          "reinvigorate": ""
        }
      },
      "RequireJS": {
        "cats": [
          12
        ],
        "js": {
          "requirejs.version": "^(.+)$\\;version:\\1"
        },
        "script": "require.*\\.js"
      },
      "Resin": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^Resin(?:/(\\S*))?\\;version:\\1"
        },
        "implies": "Java"
      },
      "Reveal.js": {
        "cats": [
          12
        ],
        "implies": "Highlight.js",
        "js": {
          "Reveal.VERSION": "^(.+)$\\;version:\\1"
        },
        "script": "(?:^|/)reveal(?:\\.min)?\\.js"
      },
      "Revel": {
        "cats": [
          18
        ],
        "cookies": {
          "REVEL_FLASH": "",
          "REVEL_SESSION": ""
        },
        "implies": "Go"
      },
      "Revslider": {
        "cats": [
          19
        ],
        "html": [
          "<link[^>]* href=[\\'\"][^']+revslider[/\\w-]+\\.css\\?ver=([0-9.]+)[\\'\"]\\;version:\\1"
        ],
        "implies": "WordPress",
        "script": "/revslider/[/\\w-]+/js"
      },
      "Rickshaw": {
        "cats": [
          25
        ],
        "implies": "D3",
        "js": {
          "Rickshaw": ""
        },
        "script": "rickshaw(?:\\.min)?\\.js"
      },
      "RightJS": {
        "cats": [
          12
        ],
        "js": {
          "RightJS": ""
        },
        "script": "right\\.js"
      },
      "Riot": {
        "cats": [
          12
        ],
        "js": {
          "riot": ""
        },
        "script": "riot(?:\\+compiler)?(?:\\.min)?\\.js"
      },
      "RiteCMS": {
        "cats": [
          1
        ],
        "implies": [
          "PHP",
          "SQLite\\;confidence:80"
        ],
        "meta": {
          "generator": "^RiteCMS(?: (.+))?\\;version:\\1"
        }
      },
      "Roadiz CMS": {
        "cats": [
          1,
          11
        ],
        "headers": {
          "X-Powered-By": "Roadiz CMS"
        },
        "implies": [
          "PHP",
          "Symfony"
        ],
        "meta": {
          "generator": "^Roadiz ([a-z0-9\\s\\.]+) - \\;version:\\1"
        }
      },
      "Robin": {
        "cats": [
          6
        ],
        "js": {
          "_robin_getRobinJs": "",
          "robin_settings": "",
          "robin_storage_settings": ""
        }
      },
      "RockRMS": {
        "cats": [
          1,
          11,
          32
        ],
        "implies": [
          "Windows Server",
          "IIS",
          "Microsoft ASP.NET"
        ],
        "meta": {
          "generator": "^Rock v([0-9.]+)\\;version:\\1"
        }
      },
      "RoundCube": {
        "cats": [
          30
        ],
        "html": "<title>RoundCube",
        "implies": "PHP",
        "js": {
          "rcmail": "",
          "roundcube": ""
        }
      },
      "Rubicon Project": {
        "cats": [
          36
        ],
        "script": "https?://[^/]*\\.rubiconproject\\.com"
      },
      "Ruby": {
        "cats": [
          27
        ],
        "headers": {
          "Server": "(?:Mongrel|WEBrick|Ruby)"
        }
      },
      "Ruby on Rails": {
        "cats": [
          18
        ],
        "headers": {
          "Server": "mod_(?:rails|rack)",
          "X-Powered-By": "mod_(?:rails|rack)"
        },
        "implies": "Ruby",
        "meta": {
          "csrf-param": "^authenticity_token$\\;confidence:50"
        },
        "cookies": {
          "_session_id": "\\;confidence:75"
        },
        "script": "/assets/application-[a-z\\d]{32}/\\.js\\;confidence:50"
      },
      "Ruxit": {
        "cats": [
          10
        ],
        "script": "ruxitagentjs"
      },
      "RxJS": {
        "cats": [
          12
        ],
        "js": {
          "Rx.CompositeDisposable": "",
          "Rx.Symbol": ""
        },
        "script": "rx(?:\\.\\w+)?(?:\\.compat|\\.global)?(?:\\.min)?\\.js"
      },
      "S.Builder": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "S\\.Builder"
        }
      },
      "SAP": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "SAP NetWeaver Application Server"
        }
      },
      "SDL Tridion": {
        "cats": [
          1
        ],
        "html": "<img[^>]+_tcm\\d{2,3}-\\d{6}\\."
      },
      "Sensors Data": {
        "cats": [
          10
        ],
        "js": {
          "sa.lib_version": "([\\d.]+)\\;version:\\1",
          "sensorsdata_app_js_bridge_call_js": ""
        },
        "cookies": {
          "sensorsdata2015session": "",
          "sensorsdata2015jssdkcross": ""
        },
        "script": "sensorsdata"
      },
      "Sentry": {
        "cats": [
          13
        ],
        "html": "<script[^>]*>\\s*Raven\\.config\\('[^']*', {\\s+release: '([0-9\\.]+)'\\;version:\\1",
        "js": {
          "Raven.config": "",
          "ravenOptions.whitelistUrls": ""
        }
      },
      "SIMsite": {
        "cats": [
          1
        ],
        "meta": {
          "SIM.medium": ""
        },
        "script": "/sim(?:site|core)/js"
      },
      "SMF": {
        "cats": [
          2
        ],
        "html": "credits/?\" title=\"Simple Machines Forum\" target=\"_blank\" class=\"new_win\">SMF ([0-9.]+)</a>\\;version:\\1",
        "implies": "PHP",
        "js": {
          "smf_": ""
        }
      },
      "SOBI 2": {
        "cats": [
          19
        ],
        "html": "(?:<!-- start of Sigsiu Online Business Index|<div[^>]* class=\"sobi2)",
        "implies": "Joomla"
      },
      "SPDY": {
        "cats": [
          19
        ],
        "excludes": "HTTP/2",
        "headers": {
          "X-Firefox-Spdy": "\\d\\.\\d"
        }
      },
      "SPIP": {
        "cats": [
          1
        ],
        "headers": {
          "Composed-By": "SPIP ([\\d.]+) @\\;version:\\1",
          "X-Spip-Cache": ""
        },
        "implies": "PHP",
        "meta": {
          "generator": "(?:^|\\s)SPIP(?:\\s([\\d.]+(?:\\s\\[\\d+\\])?))?\\;version:\\1"
        }
      },
      "SQL Buddy": {
        "cats": [
          3
        ],
        "html": "(?:<title>SQL Buddy</title>|<[^>]+onclick=\"sideMainClick\\(\"home\\.php)",
        "implies": "PHP"
      },
      "SQLite": {
        "cats": [
          34
        ]
      },
      "SUSE": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "SUSE(?:/?\\s?-?([\\d.]+))?\\;version:\\1",
          "X-Powered-By": "SUSE(?:/?\\s?-?([\\d.]+))?\\;version:\\1"
        }
      },
      "SWFObject": {
        "cats": [
          19
        ],
        "js": {
          "SWFObject": ""
        },
        "script": "swfobject.*\\.js"
      },
      "Saia PCD": {
        "cats": [
          45
        ],
        "headers": {
          "Server": "Saia PCD(?:([/a-z\\d.]+))?\\;version:\\1"
        }
      },
      "Sails.js": {
        "cats": [
          18
        ],
        "cookies": {
          "sails.sid": ""
        },
        "headers": {
          "X-Powered-By": "^Sails(?:$|[^a-z0-9])"
        },
        "implies": "Express"
      },
      "Salesforce": {
        "cats": [
          53
        ],
        "cookies": {
          "com.salesforce": ""
        },
        "html": "<[^>]+=\"brandQuaternaryFgrs\"",
        "js": {
          "SFDCApp": "",
          "SFDCCmp": "",
          "SFDCPage": "",
          "SFDCSessionVars": ""
        }
      },
      "Salesforce Commerce Cloud": {
        "cats": [
          6
        ],
        "headers": {
          "Server": "Demandware eCommerce Server"
        },
        "html": "<[^>]+demandware\\.edgesuite",
        "js": {
          "dwAnalytics": ""
        },
        "script": "/demandware\\.static/"
      },
      "Sarka-SPIP": {
        "cats": [
          1
        ],
        "implies": "SPIP",
        "meta": {
          "generator": "Sarka-SPIP(?:\\s([\\d.]+))?\\;version:\\1"
        }
      },
      "Sazito": {
        "cats": [
          6
        ],
        "js": {
          "Sazito": ""
        },
        "meta": {
          "generator": "^Sazito"
        }
      },
      "Scala": {
        "cats": [
          27
        ]
      },
      "Scholica": {
        "cats": [
          21
        ],
        "headers": {
          "X-Scholica-Version": ""
        }
      },
      "Scientific Linux": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "Scientific Linux",
          "X-Powered-By": "Scientific Linux"
        }
      },
      "SeamlessCMS": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "^Seamless\\.?CMS"
        }
      },
      "Segment": {
        "cats": [
          10
        ],
        "js": {
          "analytics": ""
        },
        "script": "cdn\\.segment\\.com/analytics\\.js"
      },
      "Select2": {
        "cats": [
          59
        ],
        "implies": "jQuery",
        "js": {
          "jQuery.fn.select2": ""
        },
        "script": "select2(?:\\.min|\\.full)?\\.js"
      },
      "Semantic-ui": {
        "cats": [
          18
        ],
        "html": [
          "<link[^>]+semantic(?:\\.min)\\.css\""
        ],
        "script": "/semantic(?:-([\\d.]+))?(?:\\.min)?\\.js\\;version:\\1"
      },
      "Sencha Touch": {
        "cats": [
          12,
          26
        ],
        "script": "sencha-touch.*\\.js"
      },
      "Serendipity": {
        "cats": [
          1,
          11
        ],
        "implies": "PHP",
        "meta": {
          "Powered-By": "Serendipity v\\.([\\d.]+)\\;version:\\1",
          "generator": "Serendipity(?: v\\.([\\d.]+))?\\;version:\\1"
        }
      },
      "Shadow": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "ShadowFramework"
        },
        "implies": "PHP"
      },
      "Shapecss": {
        "cats": [
          18
        ],
        "html": "<link[^>]* href=\"[^\"]*shapecss(?:\\.min)?\\.css",
        "js": {
          "Shapecss": ""
        },
        "script": [
          "shapecss[-.]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "/([\\d.]+)/shapecss(?:\\.min)?\\.js\\;version:\\1",
          "shapecss.*\\.js"
        ]
      },
      "ShareThis": {
        "cats": [
          5
        ],
        "js": {
          "SHARETHIS": ""
        },
        "script": "w\\.sharethis\\.com/"
      },
      "ShellInABox": {
        "cats": [
          46
        ],
        "html": [
          "<title>Shell In A Box</title>",
          "must be enabled for ShellInABox</noscript>"
        ],
        "js": {
          "ShellInABox": ""
        }
      },
      "Shiny": {
        "cats": [
          18
        ],
        "js": {
          "Shiny.addCustomMessageHandler": ""
        }
      },
      "ShinyStat": {
        "cats": [
          10
        ],
        "html": "<img[^>]*\\s+src=['\"]?https?://www\\.shinystat\\.com/cgi-bin/shinystat\\.cgi\\?[^'\"\\s>]*['\"\\s/>]",
        "js": {
          "SSsdk": ""
        },
        "script": "^https?://codice(?:business|ssl|pro|isp)?\\.shinystat\\.com/cgi-bin/getcod\\.cgi"
      },
      "Shopatron": {
        "cats": [
          6
        ],
        "html": [
          "<body class=\"shopatron",
          "<img[^>]+mediacdn\\.shopatron\\.com\\;confidence:50"
        ],
        "js": {
          "shptUrl": ""
        },
        "meta": {
          "keywords": "Shopatron"
        },
        "script": "mediacdn\\.shopatron\\.com"
      },
      "Shopcada": {
        "cats": [
          6
        ],
        "js": {
          "Shopcada": ""
        }
      },
      "Shoper": {
        "cats": [
          6
        ],
        "js": {
          "shoper": ""
        }
      },
      "Shopery": {
        "cats": [
          6
        ],
        "headers": {
          "X-Shopery": ""
        },
        "implies": [
          "PHP",
          "Symfony",
          "Elcodi"
        ]
      },
      "Shopfa": {
        "cats": [
          6
        ],
        "js": {
          "shopfa": ""
        },
        "headers": {
          "X-Powered-By": "^ShopFA ([\\d.]+)$\\;version:\\1"
        },
        "meta": {
          "generator": "^ShopFA ([\\d.]+)$\\;version:\\1"
        }
      },
      "Shopify": {
        "cats": [
          6
        ],
        "html": "<link[^>]+=['\"]//cdn\\.shopify\\.com",
        "js": {
          "Shopify": ""
        }
      },
      "Shopline": {
        "cats": [
          6
        ],
        "meta": {
          "og:image": "https\\:\\/\\/img\\.shoplineapp\\.com"
        }
      },
      "Shoptet": {
        "cats": [
          6
        ],
        "html": "<link [^>]*href=\"https?://cdn\\.myshoptet\\.com/",
        "implies": "PHP",
        "js": {
          "shoptet": ""
        },
        "meta": {
          "web_author": "^Shoptet"
        },
        "script": [
          "^https?://cdn\\.myshoptet\\.com/"
        ]
      },
      "Shopware": {
        "cats": [
          6
        ],
        "html": "<title>Shopware ([\\d\\.]+) [^<]+\\;version:\\1",
        "implies": [
          "PHP",
          "MySQL",
          "jQuery"
        ],
        "meta": {
          "application-name": "Shopware"
        },
        "script": [
          "(?:(shopware)|/web/cache/[0-9]{10}_.+)\\.js\\;version:\\1?4:5",
          "/jquery\\.shopware\\.min\\.js",
          "/engine/Shopware/"
        ]
      },
      "Signal": {
        "cats": [
          32
        ],
        "script": [
          "//s\\.btstatic\\.com/tag\\.js",
          "//s\\.thebrighttag\\.com/iframe\\?"
        ],
        "js": {
          "signalData": ""
        }
      },
      "Silva": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "SilvaCMS"
        }
      },
      "SilverStripe": {
        "cats": [
          1
        ],
        "html": "Powered by <a href=\"[^>]+SilverStripe",
        "meta": {
          "generator": "^SilverStripe"
        },
        "implies": "PHP"
      },
      "SimpleHTTP": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "SimpleHTTP(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "Simplébo": {
        "cats": [
          1
        ],
        "headers": {
          "X-ServedBy": "simplebo"
        }
      },
      "Site Meter": {
        "cats": [
          10
        ],
        "script": "sitemeter\\.com/js/counter\\.js\\?site="
      },
      "SiteCatalyst": {
        "cats": [
          10
        ],
        "js": {
          "s_INST": "",
          "s_account": "",
          "s_code": "",
          "s_objectID": ""
        },
        "script": "/s[_-]code.*\\.js"
      },
      "SiteEdit": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "SiteEdit"
        }
      },
      "Sitecore": {
        "cats": [
          1
        ],
        "cookies": {
          "SC_ANALYTICS_GLOBAL_COOKIE": ""
        },
        "html": "<img[^>]+src=\"[^>]*/~/media/[^>]+\\.ashx"
      },
      "Sitefinity": {
        "cats": [
          1
        ],
        "implies": "Microsoft ASP.NET",
        "meta": {
          "generator": "^Sitefinity (.+)$\\;version:\\1"
        }
      },
      "Sivuviidakko": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "Sivuviidakko"
        }
      },
      "Sizmek": {
        "cats": [
          36
        ],
        "html": "(?:<a [^>]*href=\"[^/]*//[^/]*serving-sys\\.com/|<img [^>]*src=\"[^/]*//[^/]*serving-sys\\.com/)",
        "script": "serving-sys\\.com/"
      },
      "Slick": {
        "cats": [
          59
        ],
        "html": "<link [^>]+(?:/([\\d.]+)/)?slick-theme\\.css\\;version:\\1",
        "implies": "jQuery",
        "script": "(?:/([\\d.]+))?/slick(?:\\.min)?\\.js\\;version:\\1"
      },
      "Slimbox": {
        "cats": [
          59
        ],
        "html": "<link [^>]*href=\"[^/]*slimbox(?:-rtl)?\\.css",
        "implies": "MooTools",
        "script": "slimbox\\.js"
      },
      "Slimbox 2": {
        "cats": [
          59
        ],
        "html": "<link [^>]*href=\"[^/]*slimbox2(?:-rtl)?\\.css",
        "implies": "jQuery",
        "script": "slimbox2\\.js"
      },
      "Smart Ad Server": {
        "cats": [
          36
        ],
        "html": "<img[^>]+smartadserver\\.com\\/call",
        "js": {
          "SmartAdServer": ""
        }
      },
      "SmartSite": {
        "cats": [
          1
        ],
        "html": "<[^>]+/smartsite\\.(?:dws|shtml)\\?id=",
        "meta": {
          "author": "Redacteur SmartInstant"
        }
      },
      "Smartstore": {
        "cats": [
          6
        ],
        "script": "smjslib\\.js"
      },
      "Snap": {
        "cats": [
          18,
          22
        ],
        "headers": {
          "Server": "Snap/([.\\d]+)\\;version:\\1"
        },
        "implies": "Haskell"
      },
      "Snap.svg": {
        "cats": [
          59
        ],
        "js": {
          "Snap.version": "^(.+)$\\;version:\\1"
        },
        "script": "snap\\.svg(?:-min)?\\.js"
      },
      "Snoobi": {
        "cats": [
          10
        ],
        "js": {
          "snoobi": ""
        },
        "script": "snoobi\\.com/snoop\\.php"
      },
      "SobiPro": {
        "cats": [
          19
        ],
        "implies": "Joomla",
        "js": {
          "SobiProUrl": ""
        }
      },
      "Socket.io": {
        "cats": [
          12
        ],
        "implies": "Node.js",
        "js": {
          "io.Socket": "",
          "io.version": "^(.+)$\\;version:\\1"
        },
        "script": "socket\\.io.*\\.js"
      },
      "SoftTr": {
        "cats": [
          6
        ],
        "meta": {
          "author": "SoftTr E-Ticaret Sitesi Yazılımı"
        }
      },
      "Solodev": {
        "cats": [
          1
        ],
        "headers": {
          "solodev_session": ""
        },
        "html": "<div class=[\"']dynamicDiv[\"'] id=[\"']dd\\.\\d\\.\\d(?:\\.\\d)?[\"']>",
        "implies": "PHP"
      },
      "Solr": {
        "cats": [
          34
        ],
        "implies": "Lucene"
      },
      "Solusquare OmniCommerce Cloud": {
        "cats": [
          6
        ],
        "cookies": {
          "_solusquare": ""
        },
        "implies": "Adobe ColdFusion",
        "meta": {
          "generator": "^Solusquare$"
        }
      },
      "Solve Media": {
        "cats": [
          16,
          36
        ],
        "js": {
          "ACPuzzle": "",
          "_ACPuzzle": "",
          "_adcopy-puzzle-image-image": "",
          "adcopy-puzzle-image-image": ""
        },
        "script": "^https?://api\\.solvemedia\\.com/"
      },
      "SonarQubes": {
        "cats": [
          47
        ],
        "html": [
          "<link href=\"/css/sonar\\.css\\?v=([\\d.]+)\\;version:\\1",
          "<title>SonarQube</title>"
        ],
        "implies": "Java",
        "js": {
          "SonarMeasures": "",
          "SonarRequest": ""
        },
        "meta": {
          "application-name": "^SonarQubes$"
        },
        "script": "^/js/bundles/sonar\\.js?v=([\\d.]+)$\\;version:\\1"
      },
      "SoundManager": {
        "cats": [
          59
        ],
        "js": {
          "BaconPlayer": "",
          "SoundManager": "",
          "soundManager.version": "V(.+) \\;version:\\1"
        }
      },
      "Sphinx": {
        "cats": [
          4
        ],
        "html": "Created using <a href=\"https?://sphinx-doc\\.org/\">Sphinx</a> ([0-9.]+)\\.\\;version:\\1",
        "js": {
          "DOCUMENTATION_OPTIONS": ""
        }
      },
      "SpiderControl iniNet": {
        "cats": [
          45
        ],
        "meta": {
          "generator": "iniNet SpiderControl"
        }
      },
      "SpinCMS": {
        "cats": [
          1
        ],
        "cookies": {
          "spincms_session": ""
        },
        "implies": "PHP"
      },
      "Splunk": {
        "cats": [
          19
        ],
        "html": "<p class=\"footer\">&copy; [-\\d]+ Splunk Inc\\.(?: Splunk ([\\d\\.]+(?: build [\\d\\.]*\\d)?))?[^<]*</p>\\;version:\\1",
        "meta": {
          "author": "Splunk Inc\\;confidence:50"
        }
      },
      "Splunkd": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Splunkd"
        }
      },
      "Spree": {
        "cats": [
          6
        ],
        "html": "(?:<link[^>]*/assets/store/all-[a-z\\d]{32}\\.css[^>]+>|<script>\\s*Spree\\.(?:routes|translations|api_key))",
        "implies": "Ruby on Rails"
      },
      "Sqreen": {
        "cats": [
          19
        ],
        "headers": {
          "X-Protected-By": "^Sqreen$"
        }
      },
      "Squarespace": {
        "cats": [
          1
        ],
        "headers": {
          "X-ServedBy": "squarespace"
        },
        "html": "<!-- This is Squarespace\\. -->",
        "js": {
          "Squarespace": ""
        }
      },
      "SquirrelMail": {
        "cats": [
          30
        ],
        "html": "<small>SquirrelMail version ([.\\d]+)[^<]*<br \\;version:\\1",
        "implies": "PHP",
        "js": {
          "squirrelmail_loginpage_onload": ""
        },
        "url": "/src/webmail\\.php(?:$|\\?)"
      },
      "Squiz Matrix": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "Squiz Matrix"
        },
        "html": "<!--\\s+Running (?:MySource|Squiz) Matrix",
        "implies": "PHP",
        "meta": {
          "generator": "Squiz Matrix"
        }
      },
      "Stackla": {
        "cats": [
          5
        ],
        "js": {
          "Stackla": ""
        },
        "script": "assetscdn\\.stackla\\.com\\/media\\/js\\/widget\\/(?:[a-zA-Z0-9.]+)?\\.js"
      },
      "Starlet": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^Plack::Handler::Starlet"
        },
        "implies": "Perl"
      },
      "Statcounter": {
        "cats": [
          10
        ],
        "js": {
          "_statcounter": "\\;confidence:100",
          "sc_project": "\\;confidence:50",
          "sc_security": "\\;confidence:50"
        },
        "script": "statcounter\\.com/counter/counter"
      },
      "Store Systems": {
        "cats": [
          6
        ],
        "html": "Shopsystem von <a href=[^>]+store-systems\\.de\"|\\.mws_boxTop"
      },
      "Storeden": {
        "cats": [
          6
        ],
        "headers": {
          "X-Powered-By": "Storeden"
        }
      },
      "Storyblok": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "storyblok"
        }
      },
      "Strapdown.js": {
        "cats": [
          12
        ],
        "implies": [
          "Bootstrap",
          "Google Code Prettify"
        ],
        "script": "strapdown\\.js"
      },
      "Strapi": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "^Strapi"
        }
      },
      "Strato": {
        "cats": [
          6
        ],
        "html": "<a href=\"http://www\\.strato\\.de/\" target=\"_blank\">"
      },
      "Stripe": {
        "cats": [
          41
        ],
        "html": "<input[^>]+data-stripe",
        "js": {
          "Stripe.version": "^(.+)$\\;version:\\1"
        },
        "script": "js\\.stripe\\.com"
      },
      "SublimeVideo": {
        "cats": [
          14
        ],
        "js": {
          "sublimevideo": ""
        },
        "script": "cdn\\.sublimevideo\\.net/js/[a-z\\d]+\\.js"
      },
      "Subrion": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-CMS": "Subrion CMS"
        },
        "implies": "PHP",
        "meta": {
          "generator": "^Subrion "
        }
      },
      "Sucuri": {
        "cats": [
          31
        ],
        "headers": {
          "x-sucuri-cache:": "",
          "x-sucuri-id": ""
        }
      },
      "Sulu": {
        "cats": [
          1
        ],
        "headers": {
          "X-Generator": "Sulu/?(.+)?$\\;version:\\1"
        },
        "implies": "Symfony"
      },
      "SumoMe": {
        "cats": [
          5,
          32
        ],
        "script": "load\\.sumome\\.com"
      },
      "SunOS": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "SunOS( [\\d\\.]+)?\\;version:\\1",
          "Servlet-engine": "SunOS( [\\d\\.]+)?\\;version:\\1"
        }
      },
      "Supersized": {
        "cats": [
          25
        ],
        "script": "supersized(?:\\.([\\d.]*[\\d]))?.*\\.js\\;version:\\1"
      },
      "Svbtle": {
        "cats": [
          11
        ],
        "meta": {
          "generator": "^Svbtle\\.com$"
        },
        "url": "^https?://[^/]+\\.svbtle\\.com"
      },
      "SweetAlert": {
        "cats": [
          59
        ],
        "html": "<link[^>]+?href=\"[^\"]+sweet-alert(?:\\.min)?\\.css",
        "js": {
          "swal": ""
        },
        "script": "sweet-alert(?:\\.min)?\\.js"
      },
      "SweetAlert2": {
        "cats": [
          59
        ],
        "excludes": "SweetAlert",
        "html": "<link[^>]+?href=\"[^\"]+sweetalert2(?:\\.min)?\\.css",
        "js": {
          "Sweetalert2": ""
        },
        "script": "sweetalert2(?:\\.all)?(?:\\.min)?\\.js"
      },
      "Swiftlet": {
        "cats": [
          18
        ],
        "headers": {
          "X-Generator": "Swiftlet",
          "X-Powered-By": "Swiftlet",
          "X-Swiftlet-Cache": ""
        },
        "html": "Powered by <a href=\"[^>]+Swiftlet",
        "implies": "PHP",
        "meta": {
          "generator": "Swiftlet"
        }
      },
      "Swiftype": {
        "cats": [
          29
        ],
        "js": {
          "Swiftype": ""
        },
        "script": "swiftype\\.com/embed\\.js$"
      },
      "Symfony": {
        "cats": [
          18
        ],
        "implies": "PHP"
      },
      "Sympa": {
        "cats": [
          30
        ],
        "meta": {
          "generator": "^Sympa$"
        },
        "html": "<a href=\"https?://www\\.sympa\\.org\">\\s*Powered by Sympa\\s*</a>",
        "implies": "Perl"
      },
      "Synology DiskStation": {
        "cats": [
          48
        ],
        "html": "<noscript><div class='syno-no-script'",
        "meta": {
          "application-name": "Synology DiskStation",
          "description": "^DiskStation provides a full-featured network attached storage"
        },
        "script": "webapi/entry\\.cgi\\?api=SYNO\\.(?:Core|Filestation)\\.Desktop\\."
      },
      "SyntaxHighlighter": {
        "cats": [
          19
        ],
        "html": "<(?:script|link)[^>]*sh(?:Core|Brush|ThemeDefault)",
        "js": {
          "SyntaxHighlighter": ""
        }
      },
      "TWiki": {
        "cats": [
          8
        ],
        "cookies": {
          "TWIKISID": ""
        },
        "html": "<img [^>]*(?:title|alt)=\"This site is powered by the TWiki collaboration platform",
        "implies": "Perl",
        "script": "(?:TWikiJavascripts|twikilib(?:\\.min)?\\.js)"
      },
      "tailwindcss": {
        "cats": [
          18
        ],
        "html": "<link[^>]+?href=\"[^\"]+tailwindcss(?:\\.min)?\\.css"
      },
      "TYPO3 CMS": {
        "cats": [
          1
        ],
        "html": [
          "<link[^>]+ href=\"typo3(?:conf|temp)/",
          "<img[^>]+ src=\"typo3(?:conf|temp)/"
        ],
        "implies": "PHP",
        "script": "^typo3(?:conf|temp)/",
        "meta": {
          "generator": "TYPO3\\s+(?:CMS\\s+)?([\\d.]+)?(?:\\s+CMS)?\\;version:\\1"
        },
        "url": "/typo3/"
      },
      "Taiga": {
        "cats": [
          13
        ],
        "implies": [
          "Django",
          "AngularJS"
        ],
        "js": {
          "taigaConfig": ""
        }
      },
      "Tawk.to": {
        "cats": [
          52
        ],
        "script": "//embed\\.tawk\\.to"
      },
      "Tealeaf": {
        "cats": [
          10
        ],
        "js": {
          "TeaLeaf": ""
        }
      },
      "Tealium": {
        "cats": [
          36
        ],
        "js": {
          "TEALIUMENABLED": ""
        },
        "script": [
          "^(?:https?:)?//tags\\.tiqcdn\\.com/",
          "/tealium/utag\\.js$"
        ]
      },
      "TeamCity": {
        "cats": [
          44
        ],
        "html": "<span class=\"versionTag\"><span class=\"vWord\">Version</span> ([\\d\\.]+)\\;version:\\1",
        "implies": [
          "Apache Tomcat",
          "Java",
          "jQuery",
          "Moment.js",
          "Prototype",
          "React",
          "Underscore.js"
        ],
        "meta": {
          "application-name": "TeamCity"
        }
      },
      "Telescope": {
        "cats": [
          1
        ],
        "implies": [
          "Meteor",
          "React"
        ],
        "js": {
          "Telescope": ""
        }
      },
      "TN Express Web": {
        "cats": [
          1
        ],
        "cookies": {
          "TNEW": ""
        },
        "implies": [
          "Tessitura"
        ]
      },
      "Tessitura": {
        "cats": [
          53
        ],
        "html": "<!--[^>]+Tessitura Version: (\\d*\\.\\d*\\.\\d*)?\\;version:\\1",
        "implies": [
          "Microsoft ASP.NET",
          "IIS",
          "Windows Server"
        ]
      },
      "Tengine": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Tengine"
        }
      },
      "Textalk": {
        "cats": [
          6
        ],
        "meta": {
          "generator": "Textalk Webshop"
        }
      },
      "Textpattern CMS": {
        "cats": [
          1
        ],
        "implies": [
          "PHP",
          "MySQL"
        ],
        "meta": {
          "generator": "Textpattern"
        }
      },
      "Thelia": {
        "cats": [
          1,
          6
        ],
        "html": "<(?:link|style|script)[^>]+/assets/frontOffice/",
        "implies": [
          "PHP",
          "Symfony"
        ]
      },
      "ThinkPHP": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "ThinkPHP"
        },
        "implies": "PHP"
      },
      "Ticimax": {
        "cats": [
          6
        ],
        "script": [
          "cdn\\.ticimax\\.com/"
        ]
      },
      "Tictail": {
        "cats": [
          6
        ],
        "html": "<link[^>]*tictail\\.com"
      },
      "TiddlyWiki": {
        "cats": [
          1,
          2,
          4,
          8
        ],
        "html": "<[^>]*type=[^>]text\\/vnd\\.tiddlywiki",
        "js": {
          "tiddler": ""
        },
        "meta": {
          "application-name": "^TiddlyWiki$",
          "copyright": "^TiddlyWiki created by Jeremy Ruston",
          "generator": "^TiddlyWiki$",
          "tiddlywiki-version": "^(.+)$\\;version:\\1"
        }
      },
      "Tiki Wiki CMS Groupware": {
        "cats": [
          1,
          2,
          8,
          11,
          13
        ],
        "meta": {
          "generator": "^Tiki"
        },
        "script": "(?:/|_)tiki"
      },
      "Tilda": {
        "cats": [
          1
        ],
        "html": "<link[^>]* href=[^>]+tilda(?:cdn|\\.ws|-blocks)",
        "script": "tilda(?:cdn|\\.ws|-blocks)"
      },
      "Timeplot": {
        "cats": [
          25
        ],
        "js": {
          "Timeplot": ""
        },
        "script": "timeplot.*\\.js"
      },
      "TinyMCE": {
        "cats": [
          24
        ],
        "js": {
          "tinyMCE.majorVersion": "([\\d.]+)\\;version:\\1"
        },
        "script": "/tiny_?mce(?:\\.min)?\\.js"
      },
      "Titan": {
        "cats": [
          36
        ],
        "js": {
          "titan": "",
          "titanEnabled": ""
        }
      },
      "TomatoCart": {
        "cats": [
          6
        ],
        "js": {
          "AjaxShoppingCart": ""
        },
        "meta": {
          "generator": "TomatoCart"
        }
      },
      "TornadoServer": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "TornadoServer(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "TotalCode": {
        "cats": [
          6
        ],
        "headers": {
          "X-Powered-By": "^TotalCode$"
        }
      },
      "Trac": {
        "cats": [
          13
        ],
        "html": [
          "<a id=\"tracpowered",
          "Powered by <a href=\"[^\"]*\"><strong>Trac(?:[ /]([\\d.]+))?\\;version:\\1"
        ],
        "implies": "Python"
      },
      "TrackJs": {
        "cats": [
          10
        ],
        "js": {
          "TrackJs": ""
        },
        "script": "tracker\\.js"
      },
      "Transifex": {
        "cats": [
          12
        ],
        "js": {
          "Transifex.live.lib_version": "(.+)\\;version:\\1"
        }
      },
      "Translucide": {
        "cats": [
          1
        ],
        "implies": [
          "PHP",
          "jQuery"
        ],
        "script": "lucide\\.init(?:\\.min)?\\.js"
      },
      "Tray": {
        "cats": [
          6
        ],
        "script": "tcdn\\.com\\.br"
      },
      "Tumblr": {
        "cats": [
          11
        ],
        "headers": {
          "X-Tumblr-User": ""
        },
        "html": "<iframe src=\"[^>]+tumblr\\.com",
        "url": "^https?://(?:www\\.)?[^/]+\\.tumblr\\.com/"
      },
      "TweenMax": {
        "cats": [
          12
        ],
        "js": {
          "TweenMax.version": "^(.+)$\\;version:\\1"
        },
        "script": "TweenMax(?:\\.min)?\\.js"
      },
      "Twilight CMS": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-CMS": "Twilight CMS"
        }
      },
      "TwistPHP": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "TwistPHP"
        },
        "implies": "PHP"
      },
      "TwistedWeb": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "TwistedWeb(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "Twitter": {
        "cats": [
          5
        ],
        "script": "//platform\\.twitter\\.com/widgets\\.js"
      },
      "Twitter Emoji (Twemoji)": {
        "cats": [
          19
        ],
        "js": {
          "twemoji": ""
        },
        "script": "twemoji(?:\\.min)?\\.js"
      },
      "Twitter Flight": {
        "cats": [
          12
        ],
        "implies": "jQuery",
        "js": {
          "flight": ""
        }
      },
      "Twitter typeahead.js": {
        "cats": [
          59
        ],
        "implies": "jQuery",
        "js": {
          "typeahead": ""
        },
        "script": "(?:typeahead|bloodhound)\\.(?:jquery|bundle)?(?:\\.min)?\\.js"
      },
      "TypePad": {
        "cats": [
          11
        ],
        "meta": {
          "generator": "typepad"
        },
        "url": "typepad\\.com"
      },
      "Typecho": {
        "cats": [
          11
        ],
        "implies": "PHP",
        "js": {
          "TypechoComment": ""
        },
        "meta": {
          "generator": "Typecho( [\\d.]+)?\\;version:\\1"
        },
        "url": "/admin/login\\.php?referer=http%3A%2F%2F"
      },
      "Typekit": {
        "cats": [
          17
        ],
        "js": {
          "Typekit.config.js": "^(.+)$\\;version:\\1"
        },
        "script": "use\\.typekit\\.com"
      },
      "UIKit": {
        "cats": [
          18
        ],
        "html": "<[^>]+class=\"[^\"]*(?:uk-container|uk-section)",
        "script": "uikit.*\\.js"
      },
      "UMI.CMS": {
        "cats": [
          1
        ],
        "headers": {
          "X-Generated-By": "UMI\\.CMS"
        },
        "implies": "PHP"
      },
      "UNIX": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "Unix"
        }
      },
      "Ubercart": {
        "cats": [
          6
        ],
        "implies": "Drupal",
        "script": "uc_cart/uc_cart_block\\.js"
      },
      "Ubuntu": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "Ubuntu",
          "X-Powered-By": "Ubuntu"
        }
      },
      "UltraCart": {
        "cats": [
          6
        ],
        "html": "<form [^>]*action=\"[^\"]*\\/cgi-bin\\/UCEditor\\?(?:[^\"]*&)?merchantId=[^\"]",
        "js": {
          "ucCatalog": ""
        },
        "script": "cgi-bin\\/UCJavaScript\\?",
        "url": "/cgi-bin/UCEditor\\?"
      },
      "Umbraco": {
        "cats": [
          1
        ],
        "headers": {
          "X-Umbraco-Version": "^(.+)$\\;version:\\1"
        },
        "html": "powered by <a href=[^>]+umbraco",
        "implies": "Microsoft ASP.NET",
        "js": {
          "UC_IMAGE_SERVICE|ITEM_INFO_SERVICE": "",
          "UC_ITEM_INFO_SERVICE": "",
          "UC_SETTINGS": "",
          "Umbraco": ""
        },
        "meta": {
          "generator": "umbraco"
        },
        "url": "/umbraco/login\\.aspx(?:$|\\?)"
      },
      "Unbounce": {
        "cats": [
          20,
          51
        ],
        "headers": {
          "X-Unbounce-PageId": ""
        },
        "script": "ubembed\\.com"
      },
      "Underscore.js": {
        "cats": [
          59
        ],
        "excludes": "Lodash",
        "js": {
          "_.VERSION": "^(.+)$\\;confidence:0\\;version:\\1",
          "_.restArguments": ""
        },
        "script": "underscore.*\\.js(?:\\?ver=([\\d.]+))?\\;version:\\1"
      },
      "Usabilla": {
        "cats": [
          13
        ],
        "js": {
          "usabilla_live": ""
        }
      },
      "user.com": {
        "cats": [
          10
        ],
        "html": "<div[^>]+/id=\"ue_widget\"",
        "js": {
          "UserEngage": ""
        }
      },
      "UserGuiding": {
        "cats": [
          58,
          10
        ],
        "implies": [
          "React",
          "webpack",
          "Node.js"
        ],
        "script": "static\\.userguiding*\\.js"
      },
      "UserLike": {
        "cats": [
          52
        ],
        "script": [
          "userlike\\.min\\.js",
          "userlikelib\\.min\\.js"
        ]
      },
      "UserRules": {
        "cats": [
          13
        ],
        "js": {
          "_usrp": ""
        }
      },
      "UserVoice": {
        "cats": [
          13
        ],
        "js": {
          "UserVoice": ""
        }
      },
      "Ushahidi": {
        "cats": [
          1,
          35
        ],
        "cookies": {
          "ushahidi": ""
        },
        "implies": [
          "PHP",
          "MySQL",
          "OpenLayers"
        ],
        "js": {
          "Ushahidi": ""
        },
        "script": "/js/ushahidi\\.js$"
      },
      "VIVVO": {
        "cats": [
          1
        ],
        "cookies": {
          "VivvoSessionId": ""
        },
        "js": {
          "vivvo": ""
        }
      },
      "VP-ASP": {
        "cats": [
          6
        ],
        "html": "<a[^>]+>Powered By VP-ASP Shopping Cart</a>",
        "implies": "Microsoft ASP.NET",
        "script": "vs350\\.js"
      },
      "VTEX": {
        "cats": [
          6
        ],
        "cookies": {
          "VtexWorkspace": ""
        },
        "headers": {
          "Server": "^VTEX IO$",
          "powered": "vtex"
        }
      },
      "VTEX Integrated Store": {
        "cats": [
          6
        ],
        "headers": {
          "X-Powered-By": "vtex-integrated-store"
        }
      },
      "Vaadin": {
        "cats": [
          18
        ],
        "implies": "Java",
        "js": {
          "vaadin": ""
        },
        "script": "vaadinBootstrap\\.js(?:\\?v=([\\d.]+))?\\;version:\\1"
      },
      "Vanilla": {
        "cats": [
          2
        ],
        "headers": {
          "X-Powered-By": "Vanilla"
        },
        "html": "<body id=\"(?:DiscussionsPage|vanilla)",
        "implies": "PHP"
      },
      "Varnish": {
        "cats": [
          23
        ],
        "headers": {
          "Via": "varnish(?: \\(Varnish/([\\d.]+)\\))?\\;version:\\1",
          "X-Varnish": "",
          "X-Varnish-Action": "",
          "X-Varnish-Age": "",
          "X-Varnish-Cache": "",
          "X-Varnish-Hostname": ""
        }
      },
      "Venda": {
        "cats": [
          6
        ],
        "headers": {
          "X-venda-hitid": ""
        }
      },
      "Veoxa": {
        "cats": [
          36
        ],
        "html": "<img [^>]*src=\"[^\"]+tracking\\.veoxa\\.com",
        "js": {
          "VuVeoxaContent": ""
        },
        "script": "tracking\\.veoxa\\.com"
      },
      "VideoJS": {
        "cats": [
          14
        ],
        "html": "<div[^>]+class=\"video-js+\">",
        "js": {
          "VideoJS": ""
        },
        "script": "zencdn\\.net/c/video\\.js"
      },
      "VigLink": {
        "cats": [
          36
        ],
        "js": {
          "vglnk": "",
          "vl_cB": "",
          "vl_disable": ""
        },
        "script": "(?:^[^/]*//[^/]*viglink\\.com/api/|vglnk\\.js)"
      },
      "Vigbo": {
        "cats": [
          1
        ],
        "cookies": {
          "_gphw_mode": ""
        },
        "html": "<link[^>]* href=[^>]+(?:\\.vigbo\\.com|\\.gophotoweb\\.com)",
        "script": "(?:\\.vigbo\\.com|\\.gophotoweb\\.com)"
      },
      "Vignette": {
        "cats": [
          1
        ],
        "html": "<[^>]+=\"vgn-?ext"
      },
      "Vimeo": {
        "cats": [
          14
        ],
        "html": "(?:<(?:param|embed)[^>]+vimeo\\.com/moogaloop|<iframe[^>]player\\.vimeo\\.com)"
      },
      "VirtueMart": {
        "cats": [
          6
        ],
        "html": "<div id=\"vmMainPage",
        "implies": "Joomla"
      },
      "Virtuoso": {
        "cats": [
          34
        ],
        "headers": {
          "Server": "Virtuoso/?([0-9.]+)?\\;version:\\1"
        },
        "meta": {
          "Copyright": "^Copyright &copy; \\d{4} OpenLink Software",
          "Keywords": "^OpenLink Virtuoso Sparql"
        },
        "url": "/sparql"
      },
      "Visual WebGUI": {
        "cats": [
          18
        ],
        "implies": "Microsoft ASP.NET",
        "js": {
          "VWGEventArgs": ""
        },
        "meta": {
          "generator": "^Visual WebGUI"
        },
        "script": "\\.js\\.wgx$",
        "url": "\\.wgx$"
      },
      "Visual Website Optimizer": {
        "cats": [
          10
        ],
        "html": [
          "<!-- (?:Start|End) Visual Website Optimizer A?Synchronous Code -->"
        ],
        "js": {
          "VWO": "",
          "__vwo": ""
        },
        "script": [
          "dev\\.visualwebsiteoptimizer\\.com"
        ]
      },
      "VisualPath": {
        "cats": [
          10
        ],
        "script": "visualpath[^/]*\\.trackset\\.it/[^/]+/track/include\\.js"
      },
      "Volusion (V1)": {
        "cats": [
          6
        ],
        "html": "<link [^>]*href=\"[^\"]*/vspfiles/",
        "implies": "Microsoft ASP.NET",
        "js": {
          "volusion": ""
        },
        "script": "/volusion\\.js(?:\\?([\\d.]*))?\\;version:\\1"
      },
      "Volusion (V2)": {
        "cats": [
          6
        ],
        "html": "<body [^>]*data-vn-page-name",
        "implies": "AngularJS"
      },
      "Vue.js": {
        "cats": [
          12
        ],
        "html": "<[^>]+data-v(?:ue)-",
        "js": {
          "Vue.version": "^(.+)$\\;version:\\1"
        },
        "script": [
          "vue[.-]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "(?:/([\\d.]+))?/vue(?:\\.min)?\\.js\\;version:\\1"
        ]
      },
      "Nuxt.js": {
        "cats": [
          12
        ],
        "html": [
          "<div [^>]*id=\"__nuxt\"",
          "<script [^>]*>window\\.__NUXT__"
        ],
        "js": {
          "$nuxt": ""
        },
        "script": [
          "/_nuxt/"
        ],
        "implies": "Vue.js"
      },
      "W3 Total Cache": {
        "cats": [
          23
        ],
        "headers": {
          "X-Powered-By": "W3 Total Cache(?:/([\\d.]+))?\\;version:\\1"
        },
        "html": "<!--[^>]+W3 Total Cache",
        "implies": "WordPress"
      },
      "W3Counter": {
        "cats": [
          10
        ],
        "script": "w3counter\\.com/tracker\\.js"
      },
      "WEBXPAY": {
        "cats": [
          6
        ],
        "html": "Powered by <a href=\"https://www\\.webxpay\\.com\">WEBXPAY<",
        "js": {
          "WEBXPAY": ""
        }
      },
      "WHMCS": {
        "cats": [
          6
        ],
        "cookies": {
          "WHMCS": ""
        }
      },
      "WP Rocket": {
        "cats": [
          23
        ],
        "headers": {
          "X-Powered-By": "WP Rocket(?:/([\\d.]+))?\\;version:\\1",
          "X-Rocket-Nginx-Bypass": ""
        },
        "html": "<!--[^>]+WP Rocket",
        "implies": "WordPress"
      },
      "WP Engine": {
        "cats": [
          62
        ],
        "headers": {
          "wpe-backend": ""
        },
        "implies": "WordPress"
      },
      "Warp": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^Warp/(\\d+(?:\\.\\d+)+)?$\\;version:\\1"
        },
        "implies": "Haskell"
      },
      "Web2py": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "web2py"
        },
        "implies": [
          "Python",
          "jQuery"
        ],
        "meta": {
          "generator": "^Web2py"
        },
        "script": "web2py\\.js"
      },
      "WebGUI": {
        "cats": [
          1
        ],
        "cookies": {
          "wgSession": ""
        },
        "implies": "Perl",
        "meta": {
          "generator": "^WebGUI ([\\d.]+)\\;version:\\1"
        }
      },
      "WebPublisher": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "WEB\\|Publisher"
        }
      },
      "WebSite X5": {
        "cats": [
          20
        ],
        "meta": {
          "generator": "Incomedia WebSite X5 (\\w+ [\\d.]+)\\;version:\\1"
        }
      },
      "Webdev": {
        "cats": [
          20
        ],
        "headers": {
          "WebDevSrc": ""
        },
        "html": "<!-- [a-zA-Z0-9_]+ [\\d/]+ [\\d:]+ WebDev \\d\\d ([\\d.]+) -->\\;version:\\1",
        "meta": {
          "generator": "^WEBDEV$"
        }
      },
      "Webix": {
        "cats": [
          12
        ],
        "js": {
          "webix": ""
        },
        "script": "\\bwebix\\.js"
      },
      "Webmine": {
        "cats": [
          56
        ],
        "html": "<iframe[^>]+src=[\\'\"]https://webmine\\.cz/miner\\?key="
      },
      "Webs": {
        "cats": [
          1
        ],
        "headers": {
          "Server": "Webs\\.com/?([\\d\\.]+)?\\;version:\\1"
        }
      },
      "Websocket": {
        "cats": [
          19
        ],
        "html": [
          "<link[^>]+rel=[\"']web-socket[\"']",
          "<(?:link|a)[^>]+href=[\"']wss?://"
        ]
      },
      "WebsPlanet": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "WebsPlanet"
        }
      },
      "Websale": {
        "cats": [
          6
        ],
        "url": "/websale7/"
      },
      "Website Creator": {
        "cats": [
          1
        ],
        "implies": [
          "PHP",
          "MySQL",
          "Vue.js"
        ],
        "meta": {
          "generator": "Website Creator by hosttech",
          "wsc_rendermode": ""
        }
      },
      "WebsiteBaker": {
        "cats": [
          1
        ],
        "implies": [
          "PHP",
          "MySQL"
        ],
        "meta": {
          "generator": "WebsiteBaker"
        }
      },
      "Webtrekk": {
        "cats": [
          10
        ],
        "js": {
          "webtrekk": ""
        }
      },
      "Webtrends": {
        "cats": [
          10
        ],
        "html": "<img[^>]+id=\"DCSIMG\"[^>]+webtrends",
        "js": {
          "WTOptimize": "",
          "WebTrends": ""
        }
      },
      "Weebly": {
        "cats": [
          1
        ],
        "implies": [
          "PHP",
          "MySQL"
        ],
        "js": {
          "_W.configDomain": ""
        },
        "script": "cdn\\d+\\.editmysite\\.com"
      },
      "Weglot": {
        "cats": [
          19
        ],
        "headers": {
          "Weglot-Translated": ""
        },
        "script": [
          "cdn\\.weglot\\.com",
          "wp-content/plugins/weglot"
        ]
      },
      "Webzi": {
        "cats": [
          1
        ],
        "js": {
          "Webzi": ""
        },
        "meta": {
          "generator": "^Webzi"
        },
        "script": "cdn\\.6th\\.ir"
      },
      "Wikinggruppen": {
        "cats": [
          6
        ],
        "html": [
          "<!-- WIKINGGRUPPEN"
        ]
      },
      "WikkaWiki": {
        "cats": [
          8
        ],
        "html": "Powered by <a href=\"[^>]+WikkaWiki",
        "meta": {
          "generator": "WikkaWiki"
        }
      },
      "Windows CE": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "\\bWinCE\\b"
        }
      },
      "Windows Server": {
        "cats": [
          28
        ],
        "headers": {
          "Server": "Win32|Win64"
        }
      },
      "Wink": {
        "cats": [
          26,
          12
        ],
        "js": {
          "wink.version": "^(.+)$\\;version:\\1"
        },
        "script": "(?:_base/js/base|wink).*\\.js"
      },
      "Winstone Servlet Container": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Winstone Servlet (?:Container|Engine) v?([\\d.]+)?\\;version:\\1",
          "X-Powered-By": "Winstone(?:.([\\d.]+))?\\;version:\\1"
        }
      },
      "Wix": {
        "cats": [
          1
        ],
        "cookies": {
          "Domain": "\\.wix\\.com"
        },
        "headers": {
          "X-Wix-Renderer-Server": "",
          "X-Wix-Request-Id": "",
          "X-Wix-Server-Artifact-Id": ""
        },
        "js": {
          "wixData": "",
          "wixErrors": "",
          "wixEvents": ""
        },
        "script": "static\\.wixstatic\\.com"
      },
      "Wolf CMS": {
        "cats": [
          1
        ],
        "html": "(?:<a href=\"[^>]+wolfcms\\.org[^>]+>Wolf CMS(?:</a>)? inside|Thank you for using <a[^>]+>Wolf CMS)",
        "implies": "PHP"
      },
      "Woltlab Community Framework": {
        "cats": [
          18
        ],
        "html": "var WCF_PATH[^>]+",
        "implies": "PHP",
        "script": "WCF\\..*\\.js"
      },
      "WooCommerce": {
        "cats": [
          6
        ],
        "html": [
          "<!-- WooCommerce",
          "<link rel='[^']+' id='woocommerce-(?:layout|smallscreen|general)-css'  href='https?://[^/]+/wp-content/plugins/woocommerce/assets/css/woocommerce(?:-layout|-smallscreen)?\\.css?ver=([\\d.]+)'\\;version:\\1"
        ],
        "implies": "WordPress",
        "js": {
          "woocommerce_params": ""
        },
        "meta": {
          "generator": "WooCommerce ([\\d.]+)\\;version:\\1"
        },
        "script": "/woocommerce(?:\\.min)?\\.js(?:\\?ver=([0-9.]+))?\\;version:\\1"
      },
      "Woopra": {
        "cats": [
          10
        ],
        "script": "static\\.woopra\\.com"
      },
      "Woosa": {
        "cats": [
          1,
          6
        ],
        "excludes": [
          "WordPress",
          "WooCommerce"
        ],
        "meta": {
          "generator": "^Woosa$"
        }
      },
      "WordPress": {
        "cats": [
          1,
          11
        ],
        "html": [
          "<link rel=[\"']stylesheet[\"'] [^>]+/wp-(?:content|includes)/",
          "<div[^>]*class=[\"']amp-wp-",
          "<link[^>]+s\\d+\\.wp\\.com"
        ],
        "implies": [
          "PHP",
          "MySQL"
        ],
        "headers": {
          "link": "rel=\"https://api\\.w\\.org/\""
        },
        "js": {
          "wp_username": ""
        },
        "meta": {
          "generator": "^WordPress ?([\\d.]+)?\\;version:\\1"
        },
        "script": "/wp-(?:content|includes)/"
      },
      "WordPress Super Cache": {
        "cats": [
          23
        ],
        "headers": {
          "WP-Super-Cache": ""
        },
        "html": "<!--[^>]+WP-Super-Cache",
        "implies": "WordPress"
      },
      "Wowza Media Server": {
        "cats": [
          38
        ],
        "html": "<title>Wowza Media Server \\d+ ((?:\\w+ Edition )?\\d+\\.[\\d\\.]+(?: build\\d+)?)?\\;version:\\1"
      },
      "X-Cart": {
        "cats": [
          6
        ],
        "cookies": {
          "xid": "[a-z\\d]{32}(?:;|$)"
        },
        "html": [
          "Powered by X-Cart(?: (\\d+))? <a[^>]+href=\"http://www\\.x-cart\\.com/\"[^>]*>\\;version:\\1",
          "<a[^>]+href=\"[^\"]*(?:\\?|&)xcart_form_id=[a-z\\d]{32}(?:&|$)"
        ],
        "implies": "PHP",
        "js": {
          "xcart_web_dir": "",
          "xliteConfig": ""
        },
        "meta": {
          "generator": "X-Cart(?: (\\d+))?\\;version:\\1"
        },
        "script": "/skin/common_files/modules/Product_Options/func\\.js"
      },
      "XAMPP": {
        "cats": [
          22
        ],
        "html": "<title>XAMPP(?: Version ([\\d\\.]+))?</title>\\;version:\\1",
        "implies": [
          "Apache",
          "MySQL",
          "PHP",
          "Perl"
        ],
        "meta": {
          "author": "Kai Oswald Seidler\\;confidence:10"
        }
      },
      "XMB": {
        "cats": [
          2
        ],
        "html": "<!-- Powered by XMB"
      },
      "XOOPS": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "js": {
          "xoops": ""
        },
        "meta": {
          "generator": "XOOPS"
        }
      },
      "XRegExp": {
        "cats": [
          59
        ],
        "js": {
          "XRegExp.version": "^(.+)$\\;version:\\1"
        },
        "script": [
          "xregexp[.-]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "/([\\d.]+)/xregexp(?:\\.min)?\\.js\\;version:\\1",
          "xregexp.*\\.js"
        ]
      },
      "XWiki": {
        "cats": [
          8
        ],
        "excludes": "MediaWiki",
        "html": [
          "<html[^>]data-xwiki-[^>]>"
        ],
        "implies": "Java\\;confidence:99",
        "meta": {
          "wiki": "xwiki"
        }
      },
      "Xajax": {
        "cats": [
          59
        ],
        "script": "xajax_core.*\\.js"
      },
      "Xanario": {
        "cats": [
          6
        ],
        "meta": {
          "generator": "xanario shopsoftware"
        }
      },
      "XenForo": {
        "cats": [
          2
        ],
        "cookies": {
          "xf_csrf": "",
          "xf_session": ""
        },
        "html": [
          "(?:jQuery\\.extend\\(true, XenForo|Forum software by XenForo™|<!--XF:branding|<html[^>]+id=\"XenForo\")",
          "<html id=\"XF\" "
        ],
        "implies": [
          "PHP",
          "MySQL"
        ],
        "js": {
          "XF.GuestUsername": ""
        }
      },
      "Xeora": {
        "cats": [
          18,
          22,
          27
        ],
        "headers": {
          "Server": "XeoraEngine",
          "X-Powered-By": "XeoraCube"
        },
        "html": "<input type=\"hidden\" name=\"_sys_bind_\\d+\" id=\"_sys_bind_\\d+\" />",
        "script": "/_bi_sps_v.+\\.js"
      },
      "Xitami": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Xitami(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "Xonic": {
        "cats": [
          6
        ],
        "html": [
          "Powered by <a href=\"http://www\\.xonic-solutions\\.de/index\\.php\" target=\"_blank\">xonic-solutions Shopsoftware</a>"
        ],
        "meta": {
          "keywords": "xonic-solutions"
        },
        "script": "core/jslib/jquery\\.xonic\\.js\\.php"
      },
      "XpressEngine": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "XpressEngine"
        }
      },
      "YUI": {
        "cats": [
          59
        ],
        "js": {
          "YAHOO.VERSION": "^(.+)$\\;version:\\1",
          "YUI.version": "^(.+)$\\;version:\\1"
        },
        "script": "(?:/yui/|yui\\.yahooapis\\.com)"
      },
      "YUI Doc": {
        "cats": [
          4
        ],
        "html": "(?:<html[^>]* yuilibrary\\.com/rdf/[\\d.]+/yui\\.rdf|<body[^>]+class=\"yui3-skin-sam)"
      },
      "YaBB": {
        "cats": [
          2
        ],
        "html": "Powered by <a href=\"[^>]+yabbforum"
      },
      "Yahoo Advertising": {
        "cats": [
          36
        ],
        "html": [
          "<iframe[^>]+adserver\\.yahoo\\.com",
          "<img[^>]+clicks\\.beap\\.bc\\.yahoo\\.com"
        ],
        "js": {
          "adxinserthtml": ""
        },
        "script": "adinterax\\.com"
      },
      "Yahoo! Ecommerce": {
        "cats": [
          6
        ],
        "headers": {
          "X-XRDS-Location": "/ystore/"
        },
        "html": "<link[^>]+store\\.yahoo\\.net",
        "js": {
          "YStore": ""
        }
      },
      "Yahoo! Tag Manager": {
        "cats": [
          42
        ],
        "html": "<!-- (?:End )?Yahoo! Tag Manager -->",
        "script": "b\\.yjtag\\.jp/iframe"
      },
      "Yahoo! Web Analytics": {
        "cats": [
          10
        ],
        "js": {
          "YWA": ""
        },
        "script": "d\\.yimg\\.com/mi/ywa\\.js"
      },
      "Yandex.Direct": {
        "cats": [
          36
        ],
        "html": "<yatag class=\"ya-partner__ads\">",
        "js": {
          "yandex_ad_format": "",
          "yandex_partner_id": ""
        },
        "script": "https?://an\\.yandex\\.ru/"
      },
      "Yandex.Metrika": {
        "cats": [
          10
        ],
        "js": {
          "yandex_metrika": ""
        },
        "script": [
          "mc\\.yandex\\.ru\\/metrika\\/watch\\.js",
          "cdn\\.jsdelivr\\.net\\/npm\\/yandex-metrica-watch\\/watch\\.js"
        ]
      },
      "Yaws": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "Yaws(?: ([\\d.]+))?\\;version:\\1"
        },
        "implies": [
          "Erlang"
        ]
      },
      "Yieldlab": {
        "cats": [
          36
        ],
        "script": "^https?://(?:[^/]+\\.)?yieldlab\\.net/"
      },
      "Yii": {
        "cats": [
          18
        ],
        "cookies": {
          "YII_CSRF_TOKEN": ""
        },
        "html": [
          "Powered by <a href=\"http://www\\.yiiframework\\.com/\" rel=\"external\">Yii Framework</a>",
          "<input type=\"hidden\" value=\"[a-zA-Z0-9]{40}\" name=\"YII_CSRF_TOKEN\" \\/>",
          "<!\\[CDATA\\[YII-BLOCK-(?:HEAD|BODY-BEGIN|BODY-END)\\]"
        ],
        "implies": [
          "PHP"
        ],
        "script": [
          "/assets/[a-zA-Z0-9]{8}\\/yii\\.js$",
          "/yii\\.(?:validation|activeForm)\\.js"
        ]
      },
      "Yoast SEO": {
        "cats": [
          54
        ],
        "html": [
          "<!-- This site is optimized with the Yoast (?:WordPress )?SEO plugin v([\\d.]+) -\\;version:\\1"
        ],
        "implies": "WordPress"
      },
      "WP-Statistics": {
        "cats": [
          59
        ],
        "html": [
          "<!-- Analytics by WP-Statistics v([\\d.]+) -\\;version:\\1"
        ],
        "implies": "WordPress"
      },
      "YouTrack": {
        "cats": [
          13
        ],
        "html": [
          "no-title=\"YouTrack\">",
          "data-reactid=\"[^\"]+\">youTrack ([0-9.]+)<\\;version:\\1",
          "type=\"application/opensearchdescription\\+xml\" title=\"YouTrack\"/>"
        ]
      },
      "YouTube": {
        "cats": [
          14
        ],
        "html": "<(?:param|embed|iframe)[^>]+youtube(?:-nocookie)?\\.com/(?:v|embed)"
      },
      "iEXExchanger": {
        "cats": [
          1
        ],
        "implies": [
          "PHP",
          "Apache",
          "Angular"
        ],
        "cookies": {
          "iexexchanger_session": ""
        },
        "meta": {
          "generator": "iEXExchanger"
        }
      },
      "ZK": {
        "cats": [
          18
        ],
        "html": "<!-- ZK [.\\d\\s]+-->",
        "implies": "Java",
        "script": "zkau/"
      },
      "ZURB Foundation": {
        "cats": [
          18
        ],
        "html": [
          "<link[^>]+foundation[^>\"]+css",
          "<div [^>]*class=\"[^\"]*(?:small|medium|large)-\\d{1,2} columns"
        ],
        "js": {
          "Foundation.version": "([\\d.]+)\\;version:\\1"
        }
      },
      "Zabbix": {
        "cats": [
          19
        ],
        "html": "<body[^>]+zbxCallPostScripts",
        "implies": "PHP",
        "js": {
          "zbxCallPostScripts": ""
        },
        "meta": {
          "Author": "ZABBIX SIA\\;confidence:70"
        },
        "url": "\\/zabbix\\/\\;confidence:30"
      },
      "Zanox": {
        "cats": [
          36
        ],
        "html": "<img [^>]*src=\"[^\"]+ad\\.zanox\\.com",
        "js": {
          "zanox": ""
        },
        "script": "zanox\\.com/scripts/zanox\\.js$"
      },
      "Zen Cart": {
        "cats": [
          6
        ],
        "meta": {
          "generator": "Zen Cart"
        }
      },
      "Zend": {
        "cats": [
          22
        ],
        "cookies": {
          "ZENDSERVERSESSID": ""
        },
        "headers": {
          "X-Powered-By": "Zend(?:Server)?(?:[\\s/]?([0-9.]+))?\\;version:\\1"
        }
      },
      "Zendesk Chat": {
        "cats": [
          52
        ],
        "script": "v2\\.zopim\\.com"
      },
      "Zenfolio": {
        "cats": [
          7
        ],
        "js": {
          "Zenfolio": ""
        }
      },
      "Zepto": {
        "cats": [
          59
        ],
        "js": {
          "Zepto": ""
        },
        "script": "zepto.*\\.js"
      },
      "Zeuscart": {
        "cats": [
          6
        ],
        "html": "<form name=\"product\" method=\"post\" action=\"[^\"]+\\?do=addtocart&prodid=\\d+\"(?!<\\/form>.)+<input type=\"hidden\" name=\"addtocart\" value=\"\\d+\">",
        "implies": "PHP",
        "url": "\\?do=prodetail&action=show&prodid=\\d+"
      },
      "Zinnia": {
        "cats": [
          11
        ],
        "implies": "Django",
        "meta": {
          "generator": "Zinnia"
        }
      },
      "Zone.js": {
        "cats": [
          12
        ],
        "js": {
          "Zone.root": ""
        }
      },
      "Zope": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "^Zope/"
        }
      },
      "a-blog cms": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "meta": {
          "generator": "a-blog cms"
        }
      },
      "actionhero.js": {
        "cats": [
          1,
          18,
          22
        ],
        "headers": {
          "X-Powered-By": "actionhero API"
        },
        "implies": "Node.js",
        "js": {
          "actionheroClient": ""
        },
        "script": "actionheroClient\\.js"
      },
      "amCharts": {
        "cats": [
          25
        ],
        "js": {
          "AmCharts": ""
        },
        "script": "amcharts.*\\.js"
      },
      "animate.css": {
        "cats": [
          18
        ],
        "html": [
          "<link [^>]+(?:/([\\d.]+)/)?animate\\.(?:min\\.)?css\\;version:\\1"
        ]
      },
      "basket.js": {
        "cats": [
          59
        ],
        "js": {
          "basket.isValidItem": ""
        },
        "script": "basket.*\\.js\\;confidence:10"
      },
      "cPanel": {
        "cats": [
          9
        ],
        "headers": {
          "Server": "cpsrvd/([\\d.]+)\\;version:\\1"
        },
        "cookies": {
          "cpsession": "",
          "cprelogin": ""
        },
        "html": "<!-- cPanel"
      },
      "cgit": {
        "cats": [
          19
        ],
        "html": [
          "<[^>]+id='cgit'",
          "generated by <a href='http://git\\.zx2c4\\.com/cgit/about/'>cgit v([\\d.a-z-]+)</a>\\;version:\\1"
        ],
        "implies": "git",
        "meta": {
          "generator": "^cgit v([\\d.a-z-]+)$\\;version:\\1"
        }
      },
      "comScore": {
        "cats": [
          10
        ],
        "html": "<iframe[^>]* (?:id=\"comscore\"|scr=[^>]+comscore)|\\.scorecardresearch\\.com/beacon\\.js|COMSCORE\\.beacon",
        "js": {
          "COMSCORE": "",
          "_COMSCORE": ""
        },
        "script": "\\.scorecardresearch\\.com/beacon\\.js|COMSCORE\\.beacon"
      },
      "debut": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "debut\\/?([\\d\\.]+)?\\;version:\\1"
        },
        "implies": "Brother"
      },
      "deepMiner": {
        "cats": [
          56
        ],
        "js": {
          "deepMiner": ""
        },
        "script": "deepMiner\\.js"
      },
      "e107": {
        "cats": [
          1
        ],
        "cookies": {
          "e107_tz": ""
        },
        "headers": {
          "X-Powered-By": "e107"
        },
        "implies": "PHP",
        "script": "[^a-z\\d]e107\\.js"
      },
      "eSyndiCat": {
        "cats": [
          1
        ],
        "headers": {
          "X-Drectory-Script": "^eSyndiCat"
        },
        "implies": "PHP",
        "js": {
          "esyndicat": ""
        },
        "meta": {
          "generator": "^eSyndiCat "
        }
      },
      "eZ Publish": {
        "cats": [
          1,
          6
        ],
        "cookies": {
          "eZSESSID": ""
        },
        "headers": {
          "X-Powered-By": "^eZ Publish"
        },
        "implies": "PHP",
        "meta": {
          "generator": "eZ Publish"
        }
      },
      "ef.js": {
        "cats": [
          12
        ],
        "js": {
          "ef.version": "^(.+)$\\;version:\\1",
          "efCore": ""
        },
        "script": "/ef(?:-core)?(?:\\.min|\\.dev)?\\.js"
      },
      "enduro.js": {
        "cats": [
          1,
          18,
          47
        ],
        "headers": {
          "X-Powered-By": "^enduro\\.js$"
        },
        "implies": "Node.js"
      },
      "git": {
        "cats": [
          47
        ],
        "meta": {
          "generator": "\\bgit/([\\d.]+\\d)\\;version:\\1"
        }
      },
      "gitlist": {
        "cats": [
          47
        ],
        "html": "<p>Powered by <a[^>]+>GitList ([\\d.]+)\\;version:\\1",
        "implies": [
          "PHP",
          "git"
        ]
      },
      "gitweb": {
        "cats": [
          47
        ],
        "html": "<!-- git web interface version ([\\d.]+)?\\;version:\\1",
        "implies": [
          "Perl",
          "git"
        ],
        "meta": {
          "generator": "gitweb(?:/([\\d.]+\\d))?\\;version:\\1"
        },
        "script": "static/gitweb\\.js$"
      },
      "govCMS": {
        "cats": [
          1
        ],
        "implies": [
          "Drupal"
        ],
        "meta": {
          "generator": "Drupal ([\\d]+) \\(http:\\/\\/drupal\\.org\\) \\+ govCMS\\;version:\\1"
        }
      },
      "gunicorn": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "gunicorn(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": "Python"
      },
      "hapi.js": {
        "cats": [
          18,
          22
        ],
        "cookies": {
          "Fe26.2**": "\\;confidence:50"
        },
        "implies": "Node.js"
      },
      "iCongo": {
        "cats": [
          6
        ],
        "implies": "Adobe ColdFusion",
        "meta": {
          "iCongo": ""
        }
      },
      "iPresta": {
        "cats": [
          6
        ],
        "implies": [
          "PHP",
          "PrestaShop"
        ],
        "meta": {
          "designer": "iPresta"
        }
      },
      "iWeb": {
        "cats": [
          20
        ],
        "meta": {
          "generator": "^iWeb( [\\d.]+)?\\;version:\\1"
        }
      },
      "ikiwiki": {
        "cats": [
          8
        ],
        "html": [
          "<link rel=\"alternate\" type=\"application/x-wiki\" title=\"Edit this page\" href=\"[^\"]*/ikiwiki\\.cgi",
          "<a href=\"/(?:cgi-bin/)?ikiwiki\\.cgi\\?do="
        ]
      },
      "imperia CMS": {
        "cats": [
          1
        ],
        "html": "<imp:live-info sysid=\"[0-9a-f-]+\"(?: node_id=\"[0-9/]*\")? *\\/>",
        "implies": "Perl",
        "meta": {
          "GENERATOR": "^IMPERIA ([0-9.]{2,})+$\\;version:\\1",
          "X-Imperia-Live-Info": ""
        },
        "url": "imperia/md/"
      },
      "io4 CMS": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "GO[ |]+CMS Enterprise"
        }
      },
      "ip-label": {
        "cats": [
          10
        ],
        "js": {
          "clobs": ""
        },
        "script": "clobs\\.js"
      },
      "jQTouch": {
        "cats": [
          26
        ],
        "js": {
          "jQT": ""
        },
        "script": "jqtouch.*\\.js"
      },
      "jQuery": {
        "cats": [
          59
        ],
        "js": {
          "jQuery.fn.jquery": "([\\d.]+)\\;version:\\1"
        },
        "script": [
          "jquery[.-]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "/([\\d.]+)/jquery(?:\\.min)?\\.js\\;version:\\1",
          "jquery.*\\.js(?:\\?ver(?:sion)?=([\\d.]+))?\\;version:\\1"
        ]
      },
      "jQuery Migrate": {
        "cats": [
          59
        ],
        "implies": "jQuery",
        "js": {
          "jQuery.migrateVersion": "([\\d.]+)\\;version:\\1",
          "jQuery.migrateWarnings": "",
          "jqueryMigrate": ""
        },
        "script": "jquery[.-]migrate(?:-([\\d.]+))?(?:\\.min)?\\.js(?:\\?ver=([\\d.]+))?\\;version:\\1?\\1:\\2"
      },
      "jQuery Mobile": {
        "cats": [
          26
        ],
        "implies": "jQuery",
        "js": {
          "jQuery.mobile.version": "^(.+)$\\;version:\\1"
        },
        "script": "jquery[.-]mobile(?:-([\\d.]))?(?:\\.min)?\\.js(?:\\?ver=([\\d.]+))?\\;version:\\1?\\1:\\2"
      },
      "jQuery-pjax": {
        "cats": [
          26
        ],
        "implies": "jQuery",
        "meta": {
          "pjax-timeout": "",
          "pjax-replace": "",
          "pjax-push": ""
        },
        "js": {
          "jQuery.pjax": ""
        },
        "script": "jquery[.-]pjax(?:-([\\d.]))?(?:\\.min)?\\.js(?:\\?ver=([\\d.]+))?\\;version:\\1?\\1:\\2",
        "html": "<div[^>]+data-pjax-container"
      },
      "jQuery Sparklines": {
        "cats": [
          25
        ],
        "implies": "jQuery",
        "script": "jquery\\.sparkline.*\\.js"
      },
      "jQuery UI": {
        "cats": [
          59
        ],
        "implies": "jQuery",
        "js": {
          "jQuery.ui.version": "^(.+)$\\;version:\\1"
        },
        "script": [
          "jquery-ui[.-]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "([\\d.]+)/jquery-ui(?:\\.min)?\\.js\\;version:\\1",
          "jquery-ui.*\\.js"
        ]
      },
      "jqPlot": {
        "cats": [
          25
        ],
        "implies": "jQuery",
        "script": "jqplot.*\\.js"
      },
      "libwww-perl-daemon": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "libwww-perl-daemon(?:/([\\d\\.]+))?\\;version:\\1"
        },
        "implies": "Perl"
      },
      "lighttpd": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "lighttpd(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "math.js": {
        "cats": [
          59
        ],
        "js": {
          "mathjs": ""
        },
        "script": "math(?:\\.min)?\\.js"
      },
      "mini_httpd": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "mini_httpd(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "mod_auth_pam": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "mod_auth_pam(?:/([\\d\\.]+))?\\;version:\\1"
        },
        "implies": "Apache"
      },
      "mod_dav": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "\\b(?:mod_)?DAV\\b(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": "Apache"
      },
      "mod_fastcgi": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "mod_fastcgi(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": "Apache"
      },
      "mod_jk": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "mod_jk(?:/([\\d\\.]+))?\\;version:\\1"
        },
        "implies": [
          "Apache Tomcat",
          "Apache"
        ]
      },
      "mod_perl": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "mod_perl(?:/([\\d\\.]+))?\\;version:\\1"
        },
        "implies": [
          "Perl",
          "Apache"
        ]
      },
      "mod_python": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "mod_python(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": [
          "Python",
          "Apache"
        ]
      },
      "mod_rack": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "mod_rack(?:/([\\d.]+))?\\;version:\\1",
          "X-Powered-By": "mod_rack(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": [
          "Ruby on Rails\\;confidence:50",
          "Apache"
        ]
      },
      "mod_rails": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "mod_rails(?:/([\\d.]+))?\\;version:\\1",
          "X-Powered-By": "mod_rails(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": [
          "Ruby on Rails\\;confidence:50",
          "Apache"
        ]
      },
      "mod_ssl": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "mod_ssl(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": "Apache"
      },
      "mod_wsgi": {
        "cats": [
          33
        ],
        "headers": {
          "Server": "mod_wsgi(?:/([\\d.]+))?\\;version:\\1",
          "X-Powered-By": "mod_wsgi(?:/([\\d.]+))?\\;version:\\1"
        },
        "implies": [
          "Python\\;confidence:50",
          "Apache"
        ]
      },
      "nopCommerce": {
        "cats": [
          6
        ],
        "cookies": {
          "Nop.customer": ""
        },
        "html": "(?:<!--Powered by nopCommerce|Powered by: <a[^>]+nopcommerce)",
        "implies": "Microsoft ASP.NET",
        "meta": {
          "generator": "^nopCommerce$"
        }
      },
      "openEngine": {
        "cats": [
          1
        ],
        "meta": {
          "openEngine": ""
        }
      },
      "osCSS": {
        "cats": [
          6
        ],
        "html": "<body onload=\"window\\.defaultStatus='oscss templates';\""
      },
      "osCommerce": {
        "cats": [
          6
        ],
        "cookies": {
          "osCsid": ""
        },
        "html": [
          "<br />Powered by <a href=\"https?://www\\.oscommerce\\.com",
          "<(?:input|a)[^>]+name=\"osCsid\"",
          "<(?:tr|td|table)class=\"[^\"]*infoBoxHeading"
        ],
        "implies": [
          "PHP",
          "MySQL"
        ]
      },
      "osTicket": {
        "cats": [
          13
        ],
        "cookies": {
          "OSTSESSID": ""
        },
        "implies": [
          "PHP",
          "MySQL"
        ]
      },
      "otrs": {
        "cats": [
          13
        ],
        "html": "<!--\\s+OTRS: Copyright \\d+-\\d+, OTRS AG",
        "implies": "Perl",
        "script": "^/otrs-web/js/"
      },
      "ownCloud": {
        "cats": [
          19
        ],
        "html": "<a href=\"https://owncloud\\.com\" target=\"_blank\">ownCloud Inc\\.</a><br/>Your Cloud, Your Data, Your Way!",
        "implies": "PHP",
        "meta": {
          "apple-itunes-app": "app-id=543672169"
        }
      },
      "papaya CMS": {
        "cats": [
          1
        ],
        "html": "<link[^>]*/papaya-themes/",
        "implies": "PHP"
      },
      "particles.js": {
        "cats": [
          25
        ],
        "html": "<div id=\"particles-js\">",
        "js": {
          "particlesJS": ""
        },
        "script": "/particles(?:\\.min)?\\.js"
      },
      "PhotoShelter": {
        "cats": [
          1
        ],
        "html": [
          "<!--\\s+#+ Powered by the PhotoShelter Beam platform",
          "<link rel=[\"']dns-prefetch[\"'] [^>]+photoshelter.com"
        ],
        "implies": [
          "PHP",
          "MySQL",
          "jQuery"
        ]
      },
      "phpAlbum": {
        "cats": [
          7
        ],
        "html": "<!--phpalbum ([.\\d\\s]+)-->\\;version:\\1",
        "implies": "PHP"
      },
      "phpBB": {
        "cats": [
          2
        ],
        "cookies": {
          "phpbb": ""
        },
        "html": [
          "Powered by <a[^>]+phpBB",
          "<div class=phpbb_copyright>",
          "<[^>]+styles/(?:sub|pro)silver/theme",
          "<img[^>]+i_icon_mini",
          "<table class=\"[^\"]*forumline"
        ],
        "implies": "PHP",
        "js": {
          "phpbb": "",
          "style_cookie_settings": ""
        },
        "meta": {
          "copyright": "phpBB Group"
        }
      },
      "phpCMS": {
        "cats": [
          1
        ],
        "implies": "PHP",
        "js": {
          "phpcms": ""
        }
      },
      "phpDocumentor": {
        "cats": [
          4
        ],
        "html": "<!-- Generated by phpDocumentor",
        "implies": "PHP"
      },
      "phpMyAdmin": {
        "cats": [
          3
        ],
        "html": "(?: \\| phpMyAdmin ([\\d.]+)<\\/title>|PMA_sendHeaderLocation\\(|<link [^>]*href=\"[^\"]*phpmyadmin\\.css\\.php)\\;version:\\1",
        "implies": [
          "PHP",
          "MySQL"
        ],
        "js": {
          "pma_absolute_uri": ""
        }
      },
      "phpPgAdmin": {
        "cats": [
          3
        ],
        "html": "(?:<title>phpPgAdmin</title>|<span class=\"appname\">phpPgAdmin)",
        "implies": "PHP"
      },
      "phpSQLiteCMS": {
        "cats": [
          1
        ],
        "implies": [
          "PHP",
          "SQLite"
        ],
        "meta": {
          "generator": "^phpSQLiteCMS(?: (.+))?$\\;version:\\1"
        }
      },
      "phpliteadmin": {
        "cats": [
          3
        ],
        "html": [
          "<span id='logo'>phpLiteAdmin</span> <span id='version'>v([0-9.]+)<\\;version:\\1",
          "<!-- Copyright [0-9]+ phpLiteAdmin (?:https?://www\\.phpliteadmin\\.org/) -->",
          "Powered by <a href='https?://www\\.phpliteadmin\\.org/'"
        ],
        "implies": [
          "PHP",
          "SQLite"
        ]
      },
      "phpwind": {
        "cats": [
          1,
          2
        ],
        "html": "(?:Powered|Code) by <a href=\"[^\"]+phpwind\\.net",
        "implies": "PHP",
        "meta": {
          "generator": "^phpwind(?: v([0-9-]+))?\\;version:\\1"
        }
      },
      "pirobase CMS": {
        "cats": [
          1
        ],
        "html": [
          "<(?:script|link)[^>]/site/[a-z0-9/._-]+/resourceCached/[a-z0-9/._-]+",
          "<input[^>]+cbi:///cms/"
        ],
        "implies": "Java"
      },
      "prettyPhoto": {
        "cats": [
          59
        ],
        "html": "(?:<link [^>]*href=\"[^\"]*prettyPhoto(?:\\.min)?\\.css|<a [^>]*rel=\"prettyPhoto)",
        "implies": "jQuery",
        "js": {
          "pp_alreadyInitialized": "",
          "pp_descriptions": "",
          "pp_images": "",
          "pp_titles": ""
        },
        "script": "jquery\\.prettyPhoto\\.js"
      },
      "punBB": {
        "cats": [
          2
        ],
        "js": {
          "PUNBB": ""
        },
        "html": "Powered by <a href=\"[^>]+punbb",
        "implies": "PHP"
      },
      "reCAPTCHA": {
        "cats": [
          16
        ],
        "html": [
          "<div[^>]+id=\"recaptcha_image",
          "<link[^>]+recaptcha",
          "<div[^>]+class=\"g-recaptcha\""
        ],
        "js": {
          "Recaptcha": "",
          "recaptcha": ""
        },
        "script": [
          "api-secure\\.recaptcha\\.net",
          "recaptcha_ajax\\.js",
          "/recaptcha/api\\.js"
        ]
      },
      "sIFR": {
        "cats": [
          17
        ],
        "script": "sifr\\.js"
      },
      "sNews": {
        "cats": [
          1
        ],
        "meta": {
          "generator": "sNews"
        }
      },
      "script.aculo.us": {
        "cats": [
          59
        ],
        "js": {
          "Scriptaculous.Version": "^(.+)$\\;version:\\1"
        },
        "script": "/(?:scriptaculous|protoaculous)(?:\\.js|/)"
      },
      "scrollreveal": {
        "cats": [
          59
        ],
        "html": "<[^>]+data-sr(?:-id)",
        "js": {
          "ScrollReveal().version": "^(.+)$\\;version:\\1"
        },
        "script": "scrollreveal(?:\\.min)(?:\\.js)"
      },
      "shine.js": {
        "cats": [
          25
        ],
        "js": {
          "Shine": ""
        },
        "script": "shine(?:\\.min)?\\.js"
      },
      "styled-components": {
        "cats": [
          12,
          47
        ],
        "html": [
          "<style[^>]*data-styled(?:-components)?[\\s\"]",
          "<style[^>]+data-styled-version=\"([0-9]+)\"\\;version:\\1"
        ],
        "implies": [
          "React"
        ],
        "js": {
          "styled": ""
        }
      },
      "swift.engine": {
        "cats": [
          1
        ],
        "headers": {
          "X-Powered-By": "swift\\.engine"
        }
      },
      "three.js": {
        "cats": [
          25
        ],
        "js": {
          "THREE.REVISION": "^(.+)$\\;version:\\1"
        },
        "script": "three(?:\\.min)?\\.js"
      },
      "thttpd": {
        "cats": [
          22
        ],
        "headers": {
          "Server": "\\bthttpd(?:/([\\d.]+))?\\;version:\\1"
        }
      },
      "total.js": {
        "cats": [
          18
        ],
        "headers": {
          "X-Powered-By": "^total\\.js"
        },
        "implies": "Node.js"
      },
      "uCore": {
        "cats": [
          1,
          18
        ],
        "cookies": {
          "ucore": ""
        },
        "implies": "PHP",
        "meta": {
          "generator": "uCore PHP Framework"
        }
      },
      "uCoz": {
        "cats": [
          1
        ],
        "cookies": {
          "uCoz": ""
        }
      },
      "uKnowva": {
        "cats": [
          1,
          2,
          18,
          50
        ],
        "headers": {
          "X-Content-Encoded-By": "uKnowva ([\\d.]+)\\;version:\\1"
        },
        "html": "<a[^>]+>Powered by uKnowva</a>",
        "implies": "PHP",
        "meta": {
          "generator": "uKnowva (?: ([\\d.]+))?\\;version:\\1"
        },
        "script": "/media/conv/js/jquery\\.js"
      },
      "vBulletin": {
        "cats": [
          2
        ],
        "html": "<div id=\"copyright\">Powered by vBulletin",
        "implies": "PHP",
        "js": {
          "vBulletin": ""
        },
        "cookies": {
          "bbsessionhash": "",
          "bblastactivity": "",
          "bblastvisit": ""
        },
        "meta": {
          "generator": "vBulletin ?([\\d.]+)?\\;version:\\1"
        }
      },
      "vibecommerce": {
        "cats": [
          6
        ],
        "excludes": "PrestaShop",
        "implies": "PHP",
        "meta": {
          "designer": "vibecommerce",
          "generator": "vibecommerce"
        }
      },
      "Virgool": {
        "cats": [
          11
        ],
        "headers": {
          "X-Powered-By": "^Virgool$"
        },
        "url": "^https?://(?:www\\.)?virgool\\.io"
      },
      "shoperfa": {
        "cats": [
          6
        ],
        "headers": {
          "X-Powered-By": "^Shoperfa$"
        },
        "url": "^https?://(?:www\\.)?shoperfa\\.com"
      },
      "webEdition": {
        "cats": [
          1
        ],
        "meta": {
          "DC.title": "webEdition",
          "generator": "webEdition"
        }
      },
      "webpack": {
        "cats": [
          19
        ],
        "js": {
          "webpackJsonp": ""
        }
      },
      "parcel": {
        "cats": [
          19
        ],
        "js": {
          "parcelRequire": ""
        }
      },
      "wpCache": {
        "cats": [
          23
        ],
        "headers": {
          "X-Powered-By": "wpCache(?:/([\\d.]+))?\\;version:\\1"
        },
        "html": "<!--[^>]+wpCache",
        "implies": [
          "WordPress",
          "PHP"
        ],
        "meta": {
          "generator": "wpCache",
          "keywords": "wpCache"
        },
        "url": "^https?://[^/]+\\.wpcache\\.co"
      },
      "xCharts": {
        "cats": [
          25
        ],
        "html": "<link[^>]* href=\"[^\"]*xcharts(?:\\.min)?\\.css",
        "implies": "D3",
        "js": {
          "xChart": ""
        },
        "script": "xcharts\\.js"
      },
      "xtCommerce": {
        "cats": [
          6
        ],
        "html": "<div class=\"copyright\">[^<]+<a[^>]+>xt:Commerce",
        "meta": {
          "generator": "xt:Commerce"
        }
      },
      "Halo": {
        "cats": [
          1,
          11
        ],
        "html": [
          "<link rel=[\"']stylesheet[\"'] [^>]+/halo-(?:backend|frontend|common)/"
        ],
        "implies": "Java",
        "script": "/halo-(?:backend|frontend|common)/"
      },
      "Rocket": {
        "cats": [
          1,
          6
        ],
        "headers": {
          "x-powered-by": "^Rocket=https://rocketcms.io/"
        },
        "implies": [
          "webpack",
          "Node.js",
          "MySQL",
          "Less"
        ]
      },
      "Zipkin": {
        "cats": [
          10
        ],
        "headers": {
          "X-B3-TraceId": "",
          "X-B3-SpanId": "",
          "X-B3-ParentSpanId": "",
          "X-B3-Sampled": "",
          "X-B3-Flags": ""
        }
      }
    },
    "categories": {
      "1": {
        "name": "CMS",
        "priority": 1
      },
      "2": {
        "name": "Message Boards",
        "priority": 1
      },
      "3": {
        "name": "Database Managers",
        "priority": 2
      },
      "4": {
        "name": "Documentation Tools",
        "priority": 2
      },
      "5": {
        "name": "Widgets",
        "priority": 9
      },
      "6": {
        "name": "Ecommerce",
        "priority": 1
      },
      "7": {
        "name": "Photo Galleries",
        "priority": 1
      },
      "8": {
        "name": "Wikis",
        "priority": 1
      },
      "9": {
        "name": "Hosting Panels",
        "priority": 1
      },
      "10": {
        "name": "Analytics",
        "priority": 9
      },
      "11": {
        "name": "Blogs",
        "priority": 1
      },
      "12": {
        "name": "JavaScript Frameworks",
        "priority": 8
      },
      "13": {
        "name": "Issue Trackers",
        "priority": 2
      },
      "14": {
        "name": "Video Players",
        "priority": 7
      },
      "15": {
        "name": "Comment Systems",
        "priority": 9
      },
      "16": {
        "name": "Captchas",
        "priority": 9
      },
      "17": {
        "name": "Font Scripts",
        "priority": 9
      },
      "18": {
        "name": "Web Frameworks",
        "priority": 7
      },
      "19": {
        "name": "Miscellaneous",
        "priority": 9
      },
      "20": {
        "name": "Editors",
        "priority": 4
      },
      "21": {
        "name": "LMS",
        "priority": 1
      },
      "22": {
        "name": "Web Servers",
        "priority": 8
      },
      "23": {
        "name": "Cache Tools",
        "priority": 7
      },
      "24": {
        "name": "Rich Text Editors",
        "priority": 5
      },
      "25": {
        "name": "JavaScript Graphics",
        "priority": 6
      },
      "26": {
        "name": "Mobile Frameworks",
        "priority": 8
      },
      "27": {
        "name": "Programming Languages",
        "priority": 5
      },
      "28": {
        "name": "Operating Systems",
        "priority": 6
      },
      "29": {
        "name": "Search Engines",
        "priority": 4
      },
      "30": {
        "name": "Web Mail",
        "priority": 2
      },
      "31": {
        "name": "CDN",
        "priority": 9
      },
      "32": {
        "name": "Marketing Automation",
        "priority": 9
      },
      "33": {
        "name": "Web Server Extensions",
        "priority": 7
      },
      "34": {
        "name": "Databases",
        "priority": 5
      },
      "35": {
        "name": "Maps",
        "priority": 6
      },
      "36": {
        "name": "Advertising Networks",
        "priority": 9
      },
      "37": {
        "name": "Network Devices",
        "priority": 2
      },
      "38": {
        "name": "Media Servers",
        "priority": 1
      },
      "39": {
        "name": "Webcams",
        "priority": 9
      },
      "41": {
        "name": "Payment Processors",
        "priority": 8
      },
      "42": {
        "name": "Tag Managers",
        "priority": 9
      },
      "44": {
        "name": "Build CI Systems",
        "priority": 3
      },
      "45": {
        "name": "Control Systems",
        "priority": 2
      },
      "46": {
        "name": "Remote Access",
        "priority": 1
      },
      "47": {
        "name": "Dev Tools",
        "priority": 2
      },
      "48": {
        "name": "Network Storage",
        "priority": 2
      },
      "49": {
        "name": "Feed Readers",
        "priority": 1
      },
      "50": {
        "name": "Document Management Systems",
        "priority": 1
      },
      "51": {
        "name": "Landing Page Builders",
        "priority": 2
      },
      "52": {
        "name": "Live Chat",
        "priority": 8
      },
      "53": {
        "name": "CRM",
        "priority": 5
      },
      "54": {
        "name": "SEO",
        "priority": 8
      },
      "55": {
        "name": "Accounting",
        "priority": 1
      },
      "56": {
        "name": "Cryptominer",
        "priority": 5
      },
      "57": {
        "name": "Static Site Generator",
        "priority": 1
      },
      "58": {
        "name": "User Onboarding",
        "priority": 8
      },
      "59": {
        "name": "JavaScript Libraries",
        "priority": 9
      },
      "60": {
        "name": "Containers",
        "priority": 8
      },
      "61": {
        "name": "SaaS",
        "priority": 8
      },
      "62": {
        "name": "PaaS",
        "priority": 8
      },
      "63": {
        "name": "IaaS",
        "priority": 8
      },
      "64": {
        "name": "Reverse Proxy",
        "priority": 7
      },
      "65": {
        "name": "Load Balancer",
        "priority": 7
      }
    }
  }