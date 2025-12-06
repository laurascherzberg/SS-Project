import copy

import MultiLabel

class MultiLabelling:
    #Can be given a map like {"x" : multilabel_x, "y" : multilabel_y}
    #dict[str → MultiLabel]
    def __init__(self, map=None):
        if map is None:
            self.map = {}
        else:
            self.map = dict(map)
    
    def get_MLByName(self, name):
        return self.map.get(name, None)
    
    def setMb(self, name, multilabel):
        self.map[name] = multilabel

    def addMultilabel(self, nameVar, MB):
        if nameVar in self.map.keys():
            self.map[nameVar] = self.map[nameVar].combine(MB)
        else:
            self.map[nameVar] = MultiLabel()

    def copy(self):
        return MultiLabelling(self.get_all())
    
    def get_all(self):
        return copy.deepcopy(self.map)
    
    def combinor(self, other):
        newMLing = MultiLabelling()

        all_keys = self.map.keys() + other.map.keys()

        for k in all_keys:
            if k in self.map.keys() and k in other.map.keys():
                newML = self.map[k].combine(other.map[k])
                newMLing.addMultilabel(k,newML)
            elif k in self.map.keys() and k not in other.map.keys():
                newMLing.addMultilabel(k, self.map[k].copy())
            elif k not in self.map.keys() and k in other.map.keys():
                newMLing.addMultilabel(k, other.map[k].copy())
        return newMLing

    