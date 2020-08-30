import matplotlib.pyplot as plt
from sklearn.metrics import auc, precision_recall_curve, roc_curve

def plot_roc(filename, y_true, y_score):
    """
    Plots the roc curve.

    Parameters
    ----------
    filename : str
        Full path to where file will be written
    y_true : list
        A list containing the true labels
    y_score : str
        A list containing the predictions
    """

    fpr, tpr, thresholds = roc_curve(y_true, y_score, pos_label=1)
    auc_roc = auc(fpr, tpr)

    plt.figure()
    lw = 2
    plt.plot(fpr, tpr, color='darkorange', lw=lw, 
             label='ROC curve (area = %0.2f)' % auc_roc)
    plt.plot([0,1], [0,1], color='navy', lw=lw, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.legend(loc="lower right")
    plt.savefig(filename)

def plot_pr(filename, y_true, y_score):
    """
    Plots the precision-recall curve.

    Parameters
    ----------
    filename : str
        Full path to where file will be written
    y_true : list
        A list containing the true labels
    y_score : str
        A list containing the predictions
    """

    precision, recall, thresholds = precision_recall_curve(y_true, y_score,
                                                           pos_label=1) 

    auc_pr = auc(recall, precision)

    plt.figure()
    lw = 2
    plt.plot(recall, precision, color='darkorange', lw=lw, 
             label='Precision Recall curve (area = %0.2f)' % auc_pr)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.legend(loc="lower right")
    plt.savefig(filename)


