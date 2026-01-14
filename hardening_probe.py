import json
from gather_info import gather_info

if __name__ =="__main__":
    result = gather_info()
    print(json.dumps(result, indent =2))



