#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

typedef struct
{double scor;
 unsigned int x,y,h,w;
 unsigned char culoare;
}FEREASTRA;

typedef struct
{unsigned char R,G,B;
}CULOARE;

void xorshift32(unsigned int **r, unsigned int width, unsigned int height, unsigned int seed)
{unsigned int i,val=seed;
 *r=(unsigned int *)malloc(2*width*height*sizeof(unsigned int));
 (*r)[0]=val;
 for(i=1;i<2*width*height;i++)
    {val=val^val<<13;
     val=val^val>>17;
     val=val^val<<5;
     (*r)[i]=val;
    }
}

void load_image(char* fisier_sursa, unsigned int **p, unsigned int *img_w, unsigned int *img_h, unsigned char **h)
{FILE *f=fopen(fisier_sursa, "rb");
 unsigned int i,j,k=0,pad;
 if(f==NULL)
    {printf("Nu exista imaginea!");
     return;
   	}
 *h=(unsigned char*)malloc(54);
 fseek(f,0,SEEK_SET);
 fread(*h,54,1,f);
 fseek(f,18,SEEK_SET);
 fread(&(*img_w),sizeof(unsigned int),1,f);
 fread(&(*img_h),sizeof(unsigned int),1,f);
 if(*img_w%4!=0)
    pad=4-(3*(*img_w))%4;
   else
    pad=0;
 *p=(unsigned int *)malloc((*img_w)*(*img_h)*sizeof(unsigned int));
 for(i=1;i<=(*img_h);i++)
    {fseek(f,-i*((*img_w)*3+pad),SEEK_END);
     for(j=1;j<=(*img_w);j++)
        {fread(&(*p)[k],3,1,f);
         k++;
        }
    }
 fclose(f);
}

void store_image(char* fisier_destinatie,unsigned int *p, unsigned int img_w, unsigned int img_h, unsigned char *h)
{FILE *f=fopen(fisier_destinatie, "wb");
 unsigned int i,j,q,k,pad,x=0;
 unsigned char *b;
 fwrite(h,54,1,f);
 if(img_w%4!=0)
    pad=4-(3*img_w)%4;
   else
    pad=0;
 for(i=1;i<=img_h;i++)
    {k=img_w*img_h-i*img_w;
     for(j=1;j<=img_w;j++)
        {b=&p[k];
         fwrite(b,3,1,f);
         k++;
        }
     for(q=0;q<pad;q++)
        fwrite(&x,1,1,f);
    }
 fclose(f);
}

void img_encrypt(char* fisier_sursa, char* fisier_destinatie, char* secret_key)
{FILE *ftxt=fopen(secret_key, "r");
 unsigned int R0,SV,*L,*CL,img_w,img_h,*R,*T,i,j,r,aux;
 unsigned char *head,*px,*pL,*pr;
 fscanf(ftxt,"%u",&R0);
 fscanf(ftxt,"%u",&SV);
 load_image(fisier_sursa,&L,&img_w,&img_h,&head);
 xorshift32(&R,img_w,img_h,R0);
 T=(unsigned int *)malloc(img_w*img_h*sizeof(unsigned int));
 CL=(unsigned int *)malloc(img_w*img_h*sizeof(unsigned int));
 for(i=0;i<img_w*img_h;i++)
    CL[i]=L[i];
 for(i=0;i<img_w*img_h;i++)
    T[i]=i;
 for(i=img_w*img_h-1;i>=1;i--)
    {r=R[img_w*img_h-i]%(i+1);
     aux=T[i];
     T[i]=T[r];
     T[r]=aux;
    }
 for(i=0;i<img_w*img_h;i++)
    L[T[i]]=CL[i];
 px=&SV;
 pL=&L[0];
 pr=&R[img_w*img_h];
 for(i=0;i<3;i++)
    pL[i]=px[i]^pL[i]^pr[i];
 for(i=1;i<img_w*img_h;i++)
    {px=&L[i-1];
     pL=&L[i];
     pr=&R[img_w*img_h+i];
     for(j=0;j<3;j++)
        pL[j]=px[j]^pL[j]^pr[j];
    }
 store_image(fisier_destinatie,L,img_w,img_h,head);
 fclose(ftxt);
 free(L);
 free(CL);
 free(R);
 free(T);
 free(head);
}

void img_decrypt(char* fisier_sursa, char* fisier_destinatie, char* secret_key)
{FILE *ftxt=fopen(secret_key, "r");
 unsigned int R0,SV,*L,*CL,img_w,img_h,*R,*T,*I,i,j,r,aux;
 unsigned char *head,*px,*pL,*pr;
 fscanf(ftxt,"%u",&R0);
 fscanf(ftxt,"%u",&SV);
 load_image(fisier_sursa,&L,&img_w,&img_h,&head);
 xorshift32(&R,img_w,img_h,R0);
 T=(unsigned int *)malloc(img_w*img_h*sizeof(unsigned int));
 I=(unsigned int *)malloc(img_w*img_h*sizeof(unsigned int));
 CL=(unsigned int *)malloc(img_w*img_h*sizeof(unsigned int));
 for(i=0;i<img_w*img_h;i++)
    T[i]=i;
 for(i=img_w*img_h-1;i>=1;i--)
    {r=R[img_w*img_h-i]%(i+1);
     aux=T[i];
     T[i]=T[r];
     T[r]=aux;
    }
 for(i=0;i<img_w*img_h;i++)
    I[T[i]]=i;
 for(i=img_w*img_h-1;i>=1;i--)
    {px=&L[i-1];
     pL=&L[i];
     pr=&R[img_w*img_h+i];
     for(j=0;j<3;j++)
        pL[j]=px[j]^pL[j]^pr[j];
    }
 px=&SV;
 pL=&L[0];
 pr=&R[img_w*img_h];
 for(i=0;i<3;i++)
    pL[i]=px[i]^pL[i]^pr[i];
 for(i=0;i<img_w*img_h;i++)
    CL[i]=L[i];
 for(i=0;i<img_w*img_h;i++)
    L[I[i]]=CL[i];
 store_image(fisier_destinatie,L,img_w,img_h,head);
 fclose(ftxt);
 free(L);
 free(CL);
 free(R);
 free(T);
 free(I);
 free(head);
}

void chisquared(char *fisier_sursa)
{FILE *f=fopen(fisier_sursa, "rb");
 unsigned int *L,img_w,img_h,i,j,k=0,pad,*R,*G,*B;
 unsigned char *p;
 double fet,vR=0,vG=0,vB=0;
 fseek(f,18,SEEK_SET);
 fread(&img_w,sizeof(unsigned int),1,f);
 fread(&img_h,sizeof(unsigned int),1,f);
 if(img_w%4!=0)
    pad=4-(3*img_w)%4;
   else
    pad=0;
 L=(unsigned int *)malloc(img_w*img_h*sizeof(unsigned int));
 for(i=1;i<=img_h;i++)
    {fseek(f,-i*(img_w*3+pad),SEEK_END);
     for(j=1;j<=img_w;j++)
        {fread(&L[k],3,1,f);
         k++;
        }
    }
 fclose(f);
 fet=(double)(img_w*img_h)/256;
 R=(unsigned int*)calloc(256,sizeof(unsigned int));
 G=(unsigned int*)calloc(256,sizeof(unsigned int));
 B=(unsigned int*)calloc(256,sizeof(unsigned int));
 for(i=0;i<img_w*img_h;i++)
    {p=&L[i];
     B[p[0]]++;
     G[p[1]]++;
     R[p[2]]++;
    }
 for(i=0;i<256;i++)
    {vR=vR+(double)((R[i]-fet)*(R[i]-fet))/fet;
     vG=vG+(double)((G[i]-fet)*(G[i]-fet))/fet;
     vB=vB+(double)((B[i]-fet)*(B[i]-fet))/fet;
    }
 printf("Chi-squared test on RGB channels for %s :\n",fisier_sursa);
 printf("R: %.2lf\n",vR);
 printf("G: %.2lf\n",vG);
 printf("B: %.2lf\n",vB);
 free(L);
 free(R);
 free(G);
 free(B);

}

void grayscale(char* nume_fisier_sursa, char* nume_fisier_destinatie)
{FILE *fin, *fout;
 unsigned int dim_img, latime_img, inaltime_img;
 unsigned char *pRGB, aux;
 pRGB=(unsigned char*)malloc(3*sizeof(unsigned char));
 fin = fopen(nume_fisier_sursa, "rb");
 if(fin == NULL)
    {printf("Imagine inexistenta!");
     return;
   	}
 fout = fopen(nume_fisier_destinatie, "wb+");
 fseek(fin, 18, SEEK_SET);
 fread(&latime_img, sizeof(unsigned int), 1, fin);
 fread(&inaltime_img, sizeof(unsigned int), 1, fin);
 fseek(fin,0,SEEK_SET);
 unsigned char c;
 while(fread(&c,1,1,fin)==1)
    {fwrite(&c,1,1,fout);
     fflush(fout);
	}
 fclose(fin);
 int padding;
 if(latime_img % 4 != 0)
    padding=4-(3*latime_img)%4;
   else
    padding=0;
 fseek(fout, 54, SEEK_SET);
 int i,j;
 for(i = 0; i < inaltime_img; i++)
    {for(j = 0; j < latime_img; j++)
		{fread(pRGB, 3, 1, fout);
         aux = 0.299*pRGB[2]+0.587*pRGB[1]+0.114*pRGB[0];
         pRGB[0]=pRGB[1]=pRGB[2]=aux;
         fseek(fout, -3, SEEK_CUR);
         fwrite(pRGB, 3, 1, fout);
         fflush(fout);
		}
     fseek(fout,padding,SEEK_CUR);
	}
 free(pRGB);
 fclose(fout);
}

void template_mathcing(char *imagine, char *sablon, double prag, FEREASTRA **p, unsigned int *dim, unsigned char nr_clr)
{unsigned int img_w,img_h,padi,s_w,s_h,pads,i,j,k,l,sb=0,m=*dim;
 unsigned char **a,**b;
 double corr,savg,favg,dsimg,dss,sumd=0,S;

 FILE *img=fopen(imagine, "rb");
 fseek(img,18,SEEK_SET);
 fread(&img_w,sizeof(unsigned int),1,img);
 fread(&img_h,sizeof(unsigned int),1,img);
 if(img_w%4!=0)
    padi=4-(3*img_w)%4;
   else
    padi=0;
 a=(unsigned char **)malloc(img_h*sizeof(unsigned char*));
 for(i=0;i<img_h;i++)
    *(a+i)=(unsigned char *)malloc(img_w*sizeof(unsigned char));
 for(i=0;i<img_h;i++)
    {fseek(img,-(i+1)*(img_w*3+padi),SEEK_END);
     for(j=0;j<img_w;j++)
        {fread(&a[i][j],1,1,img);
         fseek(img,2,SEEK_CUR);
        }
    }
 fclose(img);

 FILE *s=fopen(sablon, "rb");
 fseek(s,18,SEEK_SET);
 fread(&s_w,sizeof(unsigned int),1,s);
 fread(&s_h,sizeof(unsigned int),1,s);
 if(s_w%4!=0)
    pads=4-(3*s_w)%4;
   else
    pads=0;
 b=(unsigned char **)malloc(s_h*sizeof(unsigned char*));
 for(i=0;i<s_h;i++)
    *(b+i)=(unsigned char *)malloc(s_w*sizeof(unsigned char));
 for(i=0;i<s_h;i++)
    {fseek(s,-(i+1)*(s_w*3+pads),SEEK_END);
     for(j=0;j<s_w;j++)
        {fread(&b[i][j],1,1,s);
         sb=sb+b[i][j];
         fseek(s,2,SEEK_CUR);
        }
    }
 fclose(s);

 savg=(double)sb/(s_h*s_w);
 for(i=0;i<s_h;i++)
    for(j=0;j<s_w;j++)
        sumd=sumd+(b[i][j]-savg)*(b[i][j]-savg);
 dss=sqrt(sumd/(s_h*s_w-1));

 for(i=0;i<=img_h-s_h;i++)
    for(j=0;j<=img_w-s_w;j++)
        {sb=0;
         sumd=0;
         S=0;
         for(k=i;k<i+s_h;k++)
            {for(l=j;l<j+s_w;l++)
                sb=sb+a[k][l];
            }
         favg=(double)sb/(s_h*s_w);
         for(k=i;k<i+s_h;k++)
            {for(l=j;l<j+s_w;l++)
                sumd=sumd+(a[k][l]-favg)*(a[k][l]-favg);
            }
         dsimg=sqrt(sumd/(s_h*s_w-1));
         for(k=i;k<i+s_h;k++)
            {for(l=j;l<j+s_w;l++)
                S=S+(double)((a[k][l]-favg)*(b[k-i][l-j]-savg))/(dsimg*dss);
            }
         corr=(double)S/(s_h*s_w);
         if(corr>prag)
            {m++;
             (*p)=(FEREASTRA *)realloc((*p),m*sizeof(FEREASTRA));
             (*p)[m-1].scor=corr;
             (*p)[m-1].culoare=nr_clr;
             (*p)[m-1].x=i;
             (*p)[m-1].y=j;
             (*p)[m-1].h=s_h;
             (*p)[m-1].w=s_w;
            }
        }
 *dim=m;
 for(i=0;i<img_h;i++)
    free(a[i]);
 free(a);
 for(i=0;i<s_h;i++)
    free(b[i]);
 free(b);
}

int descrescator(const void *a, const void *b)
{FEREASTRA *va=(FEREASTRA *)a;
 FEREASTRA *vb=(FEREASTRA *)b;
 if(va->scor<vb->scor)
    return 1;
 if(va->scor>vb->scor)
    return -1;
 return 0;
}

int minim(int a, int b)
{if(a<b)
    return a;
 return b;
}

int maxim(int a, int b)
{if(a>b)
    return a;
 return b;
}

int overlap(FEREASTRA wnd1, FEREASTRA wnd2)
{unsigned int aria_1,aria_2,aria_i,aria_r;
 double supr;
 aria_1=wnd1.h*wnd1.w;
 aria_2=wnd2.h*wnd2.w;
 aria_i=maxim(minim(wnd1.x+wnd1.h-1,wnd2.x+wnd2.h-1)-maxim(wnd1.x,wnd2.x)+1,0)*maxim(minim(wnd1.y+wnd1.w-1,wnd2.y+wnd2.w-1)-maxim(wnd1.y,wnd2.y)+1,0);
 aria_r=aria_1+aria_2-aria_i;
 supr=(double)aria_i/aria_r;
 if(supr>0.2)
    return 1;
 return 0;
}

void non_maxime(FEREASTRA **p, unsigned int *dim)
{unsigned int m=*dim,i,j,k,poz;
 for(i=0;i<m-1;i++)
    for(j=i+1;j<m;j++)
        if(overlap((*p)[i],(*p)[j])==1&&(*p)[i].scor>(*p)[j].scor)
            {poz=j;
             for(k=poz+1;k<m;k++)
                (*p)[k-1]=(*p)[k];
             m--;
             j--;
            }
 *dim=m;
}

void draw(char* imagine, FEREASTRA wnd, CULOARE clr)
{unsigned int img_w,img_h,pad,i;
 FILE *f=fopen(imagine, "rb+");
 fseek(f,18,SEEK_SET);
 fread(&img_w,sizeof(unsigned int),1,f);
 fread(&img_h,sizeof(unsigned int),1,f);
 if(img_w%4!=0)
    pad=4-(3*img_w)%4;
   else
    pad=0;
 for(i=wnd.x;i<wnd.x+wnd.h;i++)
    {fseek(f,-(i+1)*(img_w*3+pad),SEEK_END);
     fseek(f,wnd.y*3,SEEK_CUR);
     fwrite(&clr.B,1,1,f);
     fwrite(&clr.G,1,1,f);
     fwrite(&clr.R,1,1,f);
     fseek(f,-(i+1)*(img_w*3+pad),SEEK_END);
     fseek(f,(wnd.y+wnd.w-1)*3,SEEK_CUR);
     fwrite(&clr.B,1,1,f);
     fwrite(&clr.G,1,1,f);
     fwrite(&clr.R,1,1,f);
    }
 fseek(f,-(wnd.x+1)*(img_w*3+pad),SEEK_END);
 fseek(f,(wnd.y+1)*3,SEEK_CUR);
 for(i=wnd.y+1;i<wnd.y+wnd.w-1;i++)
    {fwrite(&clr.B,1,1,f);
     fwrite(&clr.G,1,1,f);
     fwrite(&clr.R,1,1,f);
    }
 fseek(f,-(wnd.x+wnd.h)*(img_w*3+pad),SEEK_END);
 fseek(f,(wnd.y+1)*3,SEEK_CUR);
 for(i=wnd.y+1;i<wnd.y+wnd.w-1;i++)
    {fwrite(&clr.B,1,1,f);
     fwrite(&clr.G,1,1,f);
     fwrite(&clr.R,1,1,f);
    }
 fclose(f);
}

int main()
{   unsigned int n=0,i,nr;
    char *nume_img_init,*nume_img_criptata,*nume_img_decriptata,*nume_fis_cheie;
    nume_img_init=(char *)malloc(30*sizeof(char));
    nume_img_criptata=(char *)malloc(30*sizeof(char));
    nume_img_decriptata=(char *)malloc(30*sizeof(char));
    nume_fis_cheie=(char *)malloc(30*sizeof(char));

    printf("Numele imaginii BMP: ");
    fgets(nume_img_init,30,stdin);
    nume_img_init[strlen(nume_img_init)-1]='\0';
    printf("Numele imaginii criptate: ");
    fgets(nume_img_criptata,30,stdin);
    nume_img_criptata[strlen(nume_img_criptata)-1]='\0';
    printf("Numele imaginii decriptate: ");
    fgets(nume_img_decriptata,30,stdin);
    nume_img_decriptata[strlen(nume_img_decriptata)-1]='\0';
    printf("Numele fisier cheie secreta: ");
    fgets(nume_fis_cheie,30,stdin);
    nume_fis_cheie[strlen(nume_fis_cheie)-1]='\0';

    img_encrypt(nume_img_init,nume_img_criptata,nume_fis_cheie);
    img_decrypt(nume_img_criptata,nume_img_decriptata,nume_fis_cheie);
    chisquared(nume_img_init);
    chisquared(nume_img_criptata);

    free(nume_img_init);
    free(nume_img_criptata);
    free(nume_img_decriptata);
    free(nume_fis_cheie);

    char *img_template,*img_template_gray,**a,**b;
    img_template=(char *)malloc(30*sizeof(char));
    img_template_gray=(char *)malloc(30*sizeof(char));

    printf("Nume imagine template matching: ");
    fgets(img_template,30,stdin);
    img_template[strlen(img_template)-1]='\0';
    printf("Nume imagine template matching gri: ");
    fgets(img_template_gray,30,stdin);
    img_template_gray[strlen(img_template_gray)-1]='\0';

    printf("Numarul de sabloane: ");
    scanf("%u",&nr);
    getchar();
    CULOARE *c;
    c=(CULOARE*)malloc(sizeof(CULOARE)*nr);

    a=(char **)malloc(nr*sizeof(char*));
    for(i=0;i<nr;i++)
        a[i]=(char *)malloc(30*sizeof(char));
    b=(char **)malloc(nr*sizeof(char*));
    for(i=0;i<nr;i++)
        b[i]=(char *)malloc(30*sizeof(char));

    for(i=0;i<nr;i++)
        {printf("Nume sablon_%u: ",i);
         fgets(a[i],30,stdin);
         a[i][strlen(a[i])-1]='\0';
         printf("Nume sablon_%u_gri: ",i);
         fgets(b[i],30,stdin);
         b[i][strlen(b[i])-1]='\0';
        }

    for(i=0;i<nr;i++)
        {printf("Culori pentru sablon %u: \n",i);
         printf("R: ");
         scanf("%hhu",&c[i].R);
         printf("G: ");
         scanf("%hhu",&c[i].G);
         printf("B: ");
         scanf("%hhu",&c[i].B);
        }


    /*c[0].R=255; c[0].G=0; c[0].B=0;
    c[1].R=255; c[1].G=255; c[1].B=0;
    c[2].R=0; c[2].G=255; c[2].B=0;
    c[3].R=0; c[3].G=255; c[3].B=255;
    c[4].R=255; c[4].G=0; c[4].B=255;
    c[5].R=0; c[5].G=0; c[5].B=255;
    c[6].R=192; c[6].G=192; c[6].B=192;
    c[7].R=255; c[7].G=140; c[7].B=0;
    c[8].R=128; c[8].G=0; c[8].B=128;
    c[9].R=128; c[9].G=0; c[9].B=0;*/

    FEREASTRA *D=NULL;

    grayscale(img_template,img_template_gray);
    for(i=0;i<nr;i++)
        grayscale(a[i],b[i]);

    for(i=0;i<nr;i++)
        template_mathcing(img_template_gray,b[i],0.5,&D,&n,i);

    qsort(D,n,sizeof(FEREASTRA),descrescator);
    non_maxime(&D,&n);

    for(i=0;i<n;i++)
        draw(img_template,D[i],c[D[i].culoare]);
    free(D);
    free(c);

    for(i=0;i<nr;i++)
        free(a[i]);
    free(a);
    for(i=0;i<nr;i++)
        free(b[i]);
    free(b);

    free(img_template);
    free(img_template_gray);

    return 0;
}
