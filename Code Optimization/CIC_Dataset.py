import pandas as pd
import numpy as np
import sys
import codecs
import sklearn
from profiler import profile_each_line
import time
from line_profiler import LineProfiler
import cProfile
import random
from sklearn.preprocessing import LabelEncoder,OneHotEncoder
from sklearn import preprocessing
from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.svm import SVC
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn import metrics
import csv
from sklearn.ensemble import VotingClassifier,BaggingClassifier
from sklearn.neural_network import MLPClassifier
@profile_each_line
def model():
    sys.stdout=open("results_3.txt","w")
    testing = ["Destination Port","Flow Duration","Total Fwd Packets","Total Backward Packets",
    "Total Length of Fwd Packets","Total Length of Bwd Packets","Fwd Packet Length Max",
    "Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std","Bwd Packet Length Max",
    "Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std","Flow Bytes/s",
    "Flow Packets/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min","Fwd IAT Total",
    "Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min","Bwd IAT Total","Bwd IAT Mean",
    "Bwd IAT Std","Bwd IAT Max","Bwd IAT Min","Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags",
    "Bwd URG Flags","Fwd Header length","Bwd Header Length","Fwd Packets/s","Bwd Packets/s",
    "Min Packet Length","Max Packet Length","Packet Length Mean","Packet Length Std",
    "Packet Length Variance","FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count",
    "ACK Flag Count","URG Flag Count","CWE Flag Count","ECE Flag Count","Down/Up Ratio",
    "Average Packet Size","Avg Fwd Segment Size","Avg Bwd Segment Size","Fwd Header Length",
    "Fwd Avg Bytes/Bulk","Fwd Avg Packets/Bulk","Fwd Avg Bulk Rate","Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk","Bwd Avg Bulk Rate","Subflow Fwd Packets","Subflow Fwd Bytes",
    "Subflow Bwd Packets","Subflow Bwd Bytes","Init Win bytes forward","Init Win bytes backward",
    "act data pkt fwd","min seg size forward","Active Mean","Active Std","Active Max",
    "Active Min","Idle Mean","Idle Std","Idle Max","Idle Min","Label"]
    #print (len(testing))
    import collections
    #print ([item for item, count in collections.Counter(testing).items() if count > 1])

    import random
    
    df = pd.read_csv("train.csv",header=None,names = testing)
    
    df[~df.isin([np.isfinite]).any(1)]
    #df[~df.isin([np.inf,-np.inf,np.nan]).any(1)]


    #print(df.head())

    df_test = pd.read_csv("testt.csv", header=None,names = testing)
    df_test[~df_test.isin([np.isfinite]).any(1)]
    #df_test[~df_test.isin([np.inf,-np.inf,np.nan]).any(1)]




    dtype={'Bwd Packet Length Std': float}
    dtype={'Flow Bytes/s': float}
   # print ("hi3")
    labeldf=df['Label']
    labeldf_test=df_test['Label']

    # change the label column
    newlabeldf=labeldf.replace({ 'BENIGN' : 0, 'DDoS' : 1 })
    newlabeldf_test=labeldf_test.replace({ 'BENIGN' : 0, 'DDoS' : 1 })
    # put the new label column back

    newdf = df
    newdf_test = df_test

    newdf['Label'] = newlabeldf
    newdf_test['Label'] = newlabeldf_test



    #print(newdf['label'].value_counts())

    to_drop_DoS = [0,1]

    DoS_df=newdf[newdf['Label'].isin(to_drop_DoS)]

    #test
    DoS_df_test=newdf_test[newdf_test['Label'].isin(to_drop_DoS)]

    DoS_df = DoS_df.sample(7000)
    DoS_df_test = DoS_df_test.sample(3000)

    X_DoS = DoS_df.drop('Label',1)
    Y_DoS = DoS_df.Label

    X_DoS_test = DoS_df_test.drop('Label',1)
    Y_DoS_test = DoS_df_test.Label

    colNames=list(X_DoS)
    colNames_test=list(X_DoS_test)
    X_DoS=np.nan_to_num(X_DoS)
   # print(X_DoS)
    Y_DoS=np.nan_to_num(Y_DoS)
    print("hiiii")
    scaler1 = preprocessing.StandardScaler().fit(X_DoS)
    X_DoS=scaler1.transform(X_DoS) 

    scaler5 = preprocessing.StandardScaler().fit(X_DoS_test)
    X_DoS_test=scaler5.transform(X_DoS_test) 

   # print("Hi")

    C_values = [0.01, 0.03, 0.1, 0.3, 1, 3, 10, 30, 100]  
    gamma_values = [0.01, 0.03, 0.1, 0.3, 1, 3, 10, 30, 100]

    best_score = 0  
    best_params = {'C': None, 'gamma': None}

    for C in C_values:  
        for gamma in gamma_values:
            #clf_Rand_DoS=RandomForestClassifier(n_estimators=10,n_jobs=2)
            clf_SVM_DoS=SVC(C=C,gamma=gamma)
            #clf_NN_DoS=MLPClassifier(hidden_layer_sizes=(100, ), activation='relu', solver='adam', alpha=0.0001, batch_size='auto', learning_rate='constant', learning_rate_init=0.001, power_t=0.5, max_iter=200, shuffle=True, random_state=None, tol=0.0001, verbose=False, warm_start=False, momentum=0.9, nesterovs_momentum=True, early_stopping=False, validation_fraction=0.1, beta_1=0.9, beta_2=0.999, epsilon=1e-08, n_iter_no_change=10)

            #clf_voting_DoS = VotingClassifier(estimators=[('random', clf_Rand_DoS), ('svm', clf_SVM_DoS),('nn',clf_NN_DoS)], voting='hard')
          #  print("Tracing Code 2")
            X_DoS=np.nan_to_num(X_DoS)
            Y_DoS=np.nan_to_num(Y_DoS)
            #clf_NN_DoS.fit(X_DoS, Y_DoS.astype(int))
            #clf_voting_DoS.fit(X_DoS, Y_DoS.astype(int))
            #Y_DoS_pred=clf_voting_DoS.predict(X_DoS_test.astype(int))
            #Y_DoS_pred=clf_NN_DoS.predict(X_DoS_test.astype(int))
            @profile_each_line
            def test():
                print("C:", C)
                print("Gamma:", gamma)
                accuracy = cross_val_score(clf_SVM_DoS, X_DoS_test.astype(int), Y_DoS_test.astype(int), cv=10, scoring='accuracy')
                print("Accuracy: %0.5f (+/- %0.5f)" % (accuracy.mean(), accuracy.std() * 2))
                precision = cross_val_score(clf_SVM_DoS, X_DoS_test.astype(int), Y_DoS_test.astype(int), cv=10, scoring='precision')
                print("Precision: %0.5f (+/- %0.5f)" % (precision.mean(), precision.std() * 2))
                recall = cross_val_score(clf_SVM_DoS, X_DoS_test.astype(int), Y_DoS_test.astype(int), cv=10, scoring='recall')
                print("Recall: %0.5f (+/- %0.5f)" % (recall.mean(), recall.std() * 2))
            test()


        #print("F-measure: %0.5f (+/- %0.5f)" % (f.mean(), f.std() * 2))
model()
sys.stdout.close()
