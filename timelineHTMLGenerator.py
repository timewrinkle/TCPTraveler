'''
Created on Nov 29, 2015
@author: astrick
'''
import django
from django.template import Template, Context
from django.conf import settings

settings.configure() 

def buildPage(title, data, groupNum, groupList):

   
    template = """
 
    <!DOCTYPE HTML>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
        <title><b.{{ title }}</b></title>
        <style>
            body, html { font-family: arial, sans-serif; font-size: 11pt; }
            #visualization { box-sizing: border-box; width: 100%; height: 300px; }
        </style>
        <script src="../vis/dist/vis.js"></script>
        <link href="../vis/dist/vis.css" rel="stylesheet" type="text/css" />
        <script src="../vis/dist/googleAnalytics.js"></script>
    </head>
    <body>
       <p>{{ title }}</p>
        <div id="visualization"></div>
        <script>
            var groupCount = {{ groupNum }};

            // create a data set with groups
            var names = {{ groupList }};
            var groups = new vis.DataSet();   
            for (var g = 0; g < groupCount; g++) {
                groups.add({id: names[g], content: names[g]});
            }

            // create a dataset with items
            var items = new vis.DataSet([
                {{ data }}
            ]);
            
            // create visualization                  
            var container = document.getElementById('visualization');
            var options = {
                groupOrder: 'content'  // groupOrder can be a property name or a sorting function
            };

            var timeline = new vis.Timeline(container);
            timeline.setOptions(options);
            timeline.setGroups(groups);
            timeline.setItems(items);
          
        </script>
    </body>
    </html>
    """

    t = Template(template)
    c = Context({
        "title": title,
        "data": data,
        "groupNum": groupNum,
        "groupList": groupList
    })
    page = t.render(c)
    page2 = page.replace("&#39;","'")
    page3 = page2.replace("&lt;","<")
    page4 = page3.replace("&gt;",">")
    page5 = page4.replace("&quot;","\"")

    return page5


#test function
#buildPage("Social Media Activity Timeliner", displayLine, 5, groupList )
'''
page = buildPage("test title", "{ id:31, group: '1e100.net', content: 'lga25s40-in-f4.1e100.net', start: new Date(2015,11,30,21,29,37,000), type: 'box'}", 5, "test")
newHTMLFile =  '/Users/astrick/Programming/eclipseworkspace/Final-Social-Media-Extractor/src/testPage.html' 
print page
f = open(newHTMLFile, 'w')
f.write(page)
'''